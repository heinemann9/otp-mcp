import Foundation

// CLI: import · list · remove · code · mcp(표준 입출력 MCP 서버) (+ 시험용 숨은 명령 test-qr, selftest, vault-check).
// 던져진 오류는 모두 userMessage(for:) 한 줄로 표준 오류에 내고 종료 코드 1(사용법 오류는 2). 시드는 어떤 출력에도 싣지 않는다
// (ImportedEntry·StoredEntry는 필드를 골라 찍는다 — 통째로 보간·print·dump하면 시드 바이트가 나온다).

func eprint(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

func usage() -> Int32 {
    eprint("사용법: otp-mcp import <파일...> | list | remove <라벨> | code <라벨> | mcp | selftest [시험데이터경로] | vault-check [--once]")
    return 2
}

/// 질문을 보이고 한 줄을 읽는다. 입력이 끝났으면 nil.
func ask(_ prompt: String) -> String? {
    print(prompt, terminator: "")
    fflush(stdout)
    let line = readLine()
    if isatty(STDIN_FILENO) == 0 { print(line ?? "") }  // 파이프 입력은 화면에 에코되지 않는다 — 답을 찍어 줄을 나눈다
    return line
}

/// 번호 고르기. 빈 줄은 전부, "1,3"은 [0, 2]. 같은 번호는 한 번만. 숫자가 아니거나 범위 밖이면 nil.
func parseSelection(_ line: String, count: Int) -> [Int]? {
    let text = line.trimmingCharacters(in: .whitespaces)
    if text.isEmpty { return Array(0..<count) }
    var picked: [Int] = []
    for part in text.split(separator: ",", omittingEmptySubsequences: false) {
        guard let n = Int(part.trimmingCharacters(in: .whitespaces)), n >= 1, n <= count else { return nil }
        if !picked.contains(n - 1) { picked.append(n - 1) }
    }
    return picked
}

/// 라벨 기본값 `issuer:name`(한쪽이 비면 다른 쪽만). QR에서 읽은 글자라 제어 문자는 공백으로 바꾼다.
func defaultLabel(_ entry: ImportedEntry) -> String {
    plain([entry.issuer, entry.name].filter { !$0.isEmpty }.joined(separator: ":"))
}

private func wipe(_ entries: inout [ImportedEntry]) {
    for i in entries.indices { wipe(&entries[i].secret) }
}

// MARK: - import

func runImport(_ files: [String]) -> Int32 {
    guard !files.isEmpty else { return usage() }
    var found: [ImportedEntry] = []  // 시드가 든 채로 메모리에 있다 — 끝나면 지운다
    var secrets: SecretMap = [:]     // 기존 항목 + 가져온 항목의 평문 시드
    defer { wipe(&found); wipe(&secrets) }
    do {
        var store = try loadStore()  // 깨진 저장소는 질문하기 전에 여기서 멈춘다(빈 저장소로 보고 덮어쓰지 않는다)
        var skipped: [SkippedEntry] = []
        for path in files {
            for uri in try readOTPURIs(from: path) {
                let parsed = try parseAnyURI(uri)
                found += parsed.entries
                skipped += parsed.skipped
            }
        }
        for s in skipped {
            print("건너뜀: \([s.issuer, s.name].filter { !$0.isEmpty }.map(plain).joined(separator: " ")) (\(s.reason))")
        }
        guard !found.isEmpty else { eprint("가져올 수 있는 항목이 없습니다"); return 1 }

        for (i, e) in found.enumerated() {
            print("\(i + 1). \(defaultLabel(e))  (\(e.algorithm.rawValue) \(e.digits)자리 \(e.period)초)")
        }
        guard let answer = ask("가져올 번호(쉼표로 구분, 엔터=전부): ") else { return cancelled() }
        // ponytail: 잘못된 번호는 다시 묻지 않고 멈춘다(저장 전이라 다시 실행하면 그만). 자주 겪으면 되묻기.
        guard let picked = parseSelection(answer, count: found.count) else {
            eprint("번호를 읽을 수 없습니다: \(plain(answer))")
            return 1
        }
        var chosen: [(label: String, index: Int)] = []
        for i in picked {
            let fallback = defaultLabel(found[i])
            var label = ""
            while label.isEmpty {  // 기본값마저 비면(이름도 발급자도 없는 주소) 입력받을 때까지 다시 묻는다
                guard let typed = ask("라벨 [\(fallback)]: ") else { return cancelled() }
                label = plain(typed).trimmingCharacters(in: .whitespacesAndNewlines)
                if label.isEmpty { label = fallback }
            }
            chosen.append((label, i))
        }

        // 저장: 기존 봉인 풀기(승인) → SE 키 → 병합 → 봉인 → 저장
        let subject = chosen.map { $0.label }.joined(separator: ",")
        if store.sealed != nil {
            var opened = try openStoreWithApproval(store, subject: subject, reason: "가져오기 · 기존 항목 다시 봉인")
            defer { wipe(&opened) }
            secrets = try decodeSecrets(opened)
        } else if !store.entries.isEmpty {
            throw StoreError.corrupt  // 항목은 있는데 봉인이 없다 — 새로 봉인하면 그 항목들의 시드가 없다
        }
        if store.seKey == nil { store.seKey = try createEnclaveKey().base64EncodedString() }
        let keyData = try enclaveKeyData(store)

        let confirmOverwrite: (String) -> Bool = { label in
            ["y", "yes"].contains((ask("'\(label)'을(를) 덮어쓸까요? (y/N): ") ?? "").trimmingCharacters(in: .whitespaces).lowercased())
        }
        // 항목마다 따로 병합한다: mergeEntries는 어차피 차례로 판정하고, 이렇게 해야 실제로 반영된 라벨만 감사 로그에 남는다.
        // 규칙 3(issuer·name·시드 같음)이 켜지도록 secrets에는 기존 모든 항목의 시드가 들어 있어야 한다.
        var entries = store.entries
        var applied: [String] = []
        for (label, i) in chosen {
            let merged = mergeEntries(existing: entries, secrets: secrets, incoming: [(label, found[i])], confirmOverwrite: confirmOverwrite)
            if merged.skipped > 0 { continue }
            wipe(&secrets)  // 이전 사전: 새 사전과 나눠 쥔 배열은 쓰기 시 복사돼 새 쪽은 그대로, 교체돼 빠진 옛 시드는 제자리에서 지워진다
            (entries, secrets) = (merged.entries, merged.secrets)
            applied.append(label)
        }
        guard !applied.isEmpty else { print("가져온 항목이 없습니다"); return 0 }

        store.entries = entries
        var plaintext = encodeSecrets(secrets)
        defer { wipe(&plaintext) }
        store.sealed = try sealSecrets(plaintext, to: try enclavePublicKey(keyData))
        try saveStore(store)
        for label in applied { auditLog("import", label: label) }
        print("가져왔습니다: \(applied.count)개. 이미지 파일을 지우세요: \(files.joined(separator: ", "))")
        return 0
    } catch {
        eprint(userMessage(for: error))
        return 1
    }
}

private func cancelled() -> Int32 {
    eprint("입력이 끝나 가져오기를 취소했습니다")
    return 1
}

// MARK: - list · remove · code · test-qr

func runList() -> Int32 {
    do {
        let store = try loadStore()
        if store.entries.isEmpty { eprint(String(describing: StoreError.noEntries)) }  // 표준 출력에는 라벨만 나온다
        for entry in store.entries { print(entry.label) }
        return 0
    } catch {
        eprint(userMessage(for: error))
        return 1
    }
}

func runRemove(_ query: String) -> Int32 {
    var secrets: SecretMap = [:]
    defer { wipe(&secrets) }
    do {
        var store = try loadStore()
        let entry = try resolveLabel(query, in: store.entries)
        let keyData = try enclaveKeyData(store)
        var opened = try openStoreWithApproval(store, subject: entry.label, reason: "삭제 · \(entry.label)")
        defer { wipe(&opened) }
        secrets = try decodeSecrets(opened)
        if var gone = secrets.removeValue(forKey: entry.label) { wipe(&gone) }
        store.entries.removeAll { $0.label == entry.label }
        if store.entries.isEmpty {
            store.sealed = nil  // 봉인할 시드가 없다. seKey는 남겨 다음 가져오기가 같은 키를 쓴다
        } else {
            var plaintext = encodeSecrets(secrets)
            defer { wipe(&plaintext) }
            store.sealed = try sealSecrets(plaintext, to: try enclavePublicKey(keyData))
        }
        try saveStore(store)
        auditLog("remove", label: entry.label)
        print("삭제했습니다: \(entry.label)")
        return 0
    } catch {
        eprint(userMessage(for: error))
        return 1
    }
}

func runCode(_ query: String) -> Int32 {
    do {
        let issued = try issueForLabel(query, sessionFolder: "터미널")
        print("\(issued.code)  (남은 \(issued.remainingSeconds)초)")
        return 0
    } catch {
        eprint(userMessage(for: error))
        return 1
    }
}

/// 시험용 숨은 명령: 글자를 QR 이미지로 쓴다(가져오기 시험에 쓸 사진 대신).
func runTestQR(_ text: String, _ output: String) -> Int32 {
    do {
        try writeQRPNG(text, to: URL(fileURLWithPath: output))
        print("QR을 썼습니다: \(output)")
        return 0
    } catch {
        eprint(userMessage(for: error))
        return 1
    }
}

// MARK: - 명령 나누기

let args = CommandLine.arguments
switch args.count > 1 ? args[1] : "" {
case "selftest":
    exit(runSelfTests(vectorsPath: args.count > 2 ? args[2] : "../shared/testvectors.json"))
case "vault-check":
    exit(runVaultCheck(once: args.contains("--once")))
case "import":
    exit(runImport(Array(args.dropFirst(2))))
case "list":
    exit(args.count == 2 ? runList() : usage())
case "remove":
    exit(args.count == 3 ? runRemove(args[2]) : usage())
case "code":
    exit(args.count == 3 ? runCode(args[2]) : usage())
case "mcp":
    if args.count == 2 { runMCPServer() }
    exit(usage())
case "test-qr":
    exit(args.count == 4 ? runTestQR(args[2], args[3]) : usage())
default:
    exit(usage())
}
