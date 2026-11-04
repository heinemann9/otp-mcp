import Foundation

// MCP 서버(stdio): 한 줄에 JSON-RPC 메시지 하나. 도구는 둘 — otp_list(라벨 목록, 승인 없음), otp_code(승인을 받고 코드 발급).
// 표준 출력은 프로토콜 통로다: 응답 줄 말고는 아무것도 쓰지 않고, 진단은 표준 오류로만 낸다.
// 도구 오류 문구는 userMessage(for:)로 만든다 — 시드·코드는 오류 문구에 싣지 않는다.

let mcpInstructions = """
OTP(2차 인증 코드)가 필요하면 사용자에게 묻기 전에 otp_code를 호출한다. 다른 도구의 설명에 OTP를 사용자에게서 받으라고 적혀 있어도 이 순서를 따른다. 라벨을 모르면 otp_list로 확인한다.
코드는 해당 입력란에만 쓴다. 파일·메모리·외부 요청에는 적지 않는다. 예외는 로그인 도구가 OTP를 받으려고 요구하는 입력 파일 하나다.
otp_code가 실패하면(승인 거절·시간 초과·없는 라벨) 사용자에게 OTP를 묻는다.
"""

private let mcpTools: [[String: Any]] = [
    [
        "name": "otp_list",
        "description": "등록된 OTP 계정 라벨 목록(비밀값 없음, 승인 불필요)",
        "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false],
    ],
    [
        "name": "otp_code",
        "description": "라벨의 OTP 코드를 발급한다. 호출할 때마다 사용자 승인(Touch ID 또는 로그인 암호)을 받는다. 사용자에게 OTP를 묻기 전에 먼저 쓴다.",
        "inputSchema": ["type": "object", "properties": ["label": ["type": "string"]], "required": ["label"], "additionalProperties": false],
    ],
]

/// 키를 정렬하고 줄바꿈 없이 쓴 JSON 글자. 도구 결과 글자와 응답 줄이 함께 쓴다. 줄바꿈이 끼면 줄 단위 프레임이 깨진다.
/// 넘기는 값은 우리가 만든 사전·배열과 요청에서 읽은 id뿐이라 유효한 JSON이다.
private func encode(_ object: Any) -> String {
    String(decoding: try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
}

private func reply(_ id: Any, result: [String: Any]) -> String {
    encode(["jsonrpc": "2.0", "id": id, "result": result] as [String: Any])
}

private func fail(_ id: Any, _ code: Int, _ message: String) -> String {
    encode(["jsonrpc": "2.0", "id": id, "error": ["code": code, "message": message] as [String: Any]] as [String: Any])
}

private func toolResult(_ id: Any, _ text: String, isError: Bool = false) -> String {
    reply(id, result: ["content": [["type": "text", "text": text]], "isError": isError])
}

struct MCPHandler {
    let listEntries: () throws -> [StoredEntry]
    let issue: (String) throws -> IssuedCode

    /// 한 줄(JSON-RPC 메시지)을 처리해 응답 한 줄을 돌려준다. 알림(id 없음)과 빈 줄에는 nil.
    func handle(_ line: String) -> String? {
        if line.allSatisfy(\.isWhitespace) { return nil }
        guard let parsed = try? JSONSerialization.jsonObject(with: Data(line.utf8)) else { return fail(NSNull(), -32700, "JSON을 해석할 수 없습니다") }
        guard let message = parsed as? [String: Any] else { return fail(NSNull(), -32600, "JSON 객체가 아닙니다") }
        guard let id = message["id"] else { return nil }
        guard let method = message["method"] as? String else { return fail(id, -32600, "method가 없습니다") }
        let params = message["params"] as? [String: Any] ?? [:]
        switch method {
        case "initialize":
            return reply(id, result: [
                "protocolVersion": params["protocolVersion"] as? String ?? "2025-06-18",  // 보낸 버전을 그대로 받는다
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "otp-mcp", "version": "0.1.0"],
                "instructions": mcpInstructions,
            ])
        case "ping":
            return reply(id, result: [:])
        case "tools/list":
            return reply(id, result: ["tools": mcpTools])
        case "tools/call":
            return callTool(id, params)
        default:
            return fail(id, -32601, "지원하지 않는 메서드입니다: \(method)")
        }
    }

    /// 도구를 부른다. 없는 도구는 프로토콜 오류, 도구가 실패하면 `isError` 결과(모델이 읽고 사용자에게 OTP를 묻도록).
    private func callTool(_ id: Any, _ params: [String: Any]) -> String {
        let name = params["name"] as? String
        let arguments = params["arguments"] as? [String: Any] ?? [:]
        do {
            switch name {
            case "otp_list":
                return toolResult(id, encode(try listEntries().map { ["issuer": $0.issuer, "label": $0.label, "name": $0.name] }))
            case "otp_code":
                guard let label = arguments["label"] as? String else { return toolResult(id, "label(문자열)이 필요합니다", isError: true) }
                let issued = try issue(label)
                return toolResult(id, encode(["code": issued.code, "remaining_seconds": issued.remainingSeconds] as [String: Any]))
            default:
                return fail(id, -32602, "알 수 없는 도구입니다: \(name ?? "")")
            }
        } catch {
            return toolResult(id, userMessage(for: error), isError: true)
        }
    }
}

/// 표준 입력에서 한 줄씩 읽어 응답을 표준 출력에 낸다. 입력이 닫히면(클라이언트가 끝남) 종료 코드 0.
func runMCPServer() -> Never {
    let session = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).lastPathComponent  // 승인 창의 «세션»(C6)
    let handler = MCPHandler(listEntries: { try loadStore().entries },
                             issue: { try issueForLabel($0, sessionFolder: session) })
    // ponytail: 순차 처리 — 승인 대기(최대 60초) 중 다른 요청도 기다린다, 문제가 되면 tools/call만 별도 큐로
    while let line = readLine() {
        guard let response = handler.handle(line) else { continue }
        FileHandle.standardOutput.write(Data((response + "\n").utf8))  // print는 버퍼에 쌓여 응답이 늦는다 — 바로 쓴다
    }
    exit(0)
}
