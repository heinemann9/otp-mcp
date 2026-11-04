import Foundation

// 감사 로그: 승인 요청·승인 결과·발급·가져오기·삭제를 한 줄씩 남긴다. 코드·시드·비밀값은 받지도 않으니 새어 들어갈 길이 없다.
// 한 줄 = `ISO8601⇥event⇥label⇥ppid=<부모 PID>⇥cwd=<작업 폴더>` (⇥는 탭)
// event: approval_requested · approval_granted · approval_denied · approval_timeout · issued · import · remove

/// 탭·줄바꿈·ESC 같은 제어 문자를 공백으로 바꾼다. 라벨이나 폴더 이름이 한 줄 5칸 형식을 깨거나,
/// 가짜 줄·터미널 제어열을 끼워 넣지 못하게 한다. CLI도 QR에서 읽은 글자를 화면에 낼 때 쓴다.
func plain(_ s: String) -> String {
    String(s.unicodeScalars.map { $0.properties.generalCategory == .control ? " " : Character($0) })
}

// ponytail: 로그 회전이 없다 — 발급 한 번에 몇 줄뿐이라 느리게 자란다. 커지면 newsyslog.
/// 쓰기에 실패해도 호출한 쪽 일(발급 등)을 막지 않는다 — 표준 오류에만 알린다(MCP 모드에서 표준 출력은 프로토콜 통로다).
func auditLog(_ event: String, label: String) {
    let fields = [ISO8601DateFormatter().string(from: Date()), event, label,
                  "ppid=\(getppid())", "cwd=\(FileManager.default.currentDirectoryPath)"]
    let bytes = Array((fields.map(plain).joined(separator: "\t") + "\n").utf8)
    let url = logURL()
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o700])
    let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)  // O_APPEND: 세션이 동시에 써도 줄이 섞이지 않는다
    guard fd >= 0 else { return reportFailure(url, errno) }
    defer { close(fd) }
    if write(fd, bytes, bytes.count) != bytes.count { reportFailure(url, errno) }
}

private func reportFailure(_ url: URL, _ err: Int32) {
    FileHandle.standardError.write(Data("감사 로그를 쓰지 못했습니다: \(url.path) — \(String(cString: strerror(err)))\n".utf8))
}
