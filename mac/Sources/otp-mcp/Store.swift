import Foundation

// 저장 파일(store.json) = 평문 메타데이터(라벨·issuer·이름·알고리즘·자릿수·주기) + 봉인된 시드 묶음.
// 시드는 `sealed` 안에만 있다. 이 파일의 어떤 필드에도 평문 시드를 넣지 않는다.
// `SecretMap` 인코딩은 봉인하기 전의 평문용이라 디스크에 그대로 쓰지 않는다.

struct StoredEntry: Codable, Equatable {
    var label: String
    var issuer: String
    var name: String
    var algorithm: OTPAlgorithm
    var digits: Int
    var period: Int
    var uniqueID: String?
}

struct StoreFile: Codable, Equatable {
    var version: Int
    var seKey: String?        // Base64(Secure Enclave 키의 dataRepresentation) — 이 기기의 SE에서만 쓸 수 있다
    var entries: [StoredEntry]
    var sealed: SealedSecrets?  // 모든 시드를 한 묶음으로 봉인한 것. 항목이 없으면 nil
    static let empty = StoreFile(version: 1, seKey: nil, entries: [], sealed: nil)
}

enum StoreError: Error, CustomStringConvertible {
    case corrupt
    case noEntries
    case unknownLabel(String, available: [String])

    var description: String {
        switch self {
        case .corrupt: return "저장 파일을 읽을 수 없습니다"
        case .noEntries: return "등록된 계정이 없습니다 — otp-mcp import로 먼저 가져오세요"
        case .unknownLabel(let q, let available): return "'\(q)' 라벨이 없습니다. 등록된 라벨: \(available.joined(separator: ", "))"
        }
    }
}

// MARK: - 위치

/// `OTP_MCP_HOME`이 비어 있지 않으면 그 폴더. 부를 때마다 읽는다(시험이 `setenv`로 바꾼다).
private func envHome() -> URL? {
    guard let p = getenv("OTP_MCP_HOME"), p.pointee != 0 else { return nil }
    return URL(fileURLWithPath: String(cString: p), isDirectory: true)
}

/// 저장 폴더: `OTP_MCP_HOME` 또는 `~/Library/Application Support/otp-mcp`.
func otpHome() -> URL {
    envHome() ?? FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/otp-mcp", isDirectory: true)
}

func storeURL() -> URL { otpHome().appendingPathComponent("store.json") }

/// 감사 로그: `OTP_MCP_HOME`이 있으면 그 폴더의 `otp-mcp.log`, 없으면 `~/Library/Logs/otp-mcp.log`.
func logURL() -> URL {
    envHome()?.appendingPathComponent("otp-mcp.log")
        ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/otp-mcp.log")
}

// MARK: - 읽기·쓰기

/// 파일이 없으면 빈 저장소. 읽지 못하거나 해석에 실패하면 `.corrupt` — «없음»으로 덮으면 다음 저장이 남은 봉인을 지운다.
func loadStore() throws -> StoreFile {
    guard FileManager.default.fileExists(atPath: storeURL().path) else { return .empty }
    guard let data = try? Data(contentsOf: storeURL()),
          let store = try? JSONDecoder().decode(StoreFile.self, from: data) else { throw StoreError.corrupt }
    return store
}

private func posixError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }

// ponytail: 파일 잠금이 없다 — 가져오기·삭제를 동시에 두 번 돌리면 나중 쓰기가 이긴다(수동 CLI라 드묾). 필요해지면 flock.
// ponytail: 폴더 0700은 새로 만들 때만 건다. 이미 있던 폴더(OTP_MCP_HOME이 가리키는 곳)의 권한은 바꾸지 않는다.
/// 같은 폴더의 임시 파일에 0600으로 쓰고 디스크에 닿게 한 뒤 `rename`으로 바꾼다 —
/// 동시에 떠 있는 세션이 반쯤 쓴 파일을 읽지 못하고, 중간에 죽어도 옛 파일이 그대로 남는다.
func saveStore(_ s: StoreFile) throws {
    try FileManager.default.createDirectory(at: otpHome(), withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(s)

    let tmp = otpHome().appendingPathComponent("store.json.\(UUID().uuidString).tmp").path
    let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0o600)  // 만들 때부터 0600 — 만든 뒤 chmod하는 틈이 없다(umask는 깎기만 한다)
    guard fd >= 0 else { throw posixError() }
    let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    do {
        try file.write(contentsOf: data)
        try file.synchronize()
        try file.close()
        guard rename(tmp, storeURL().path) == 0 else { throw posixError() }
    } catch {
        try? FileManager.default.removeItem(atPath: tmp)
        throw error
    }
}

// MARK: - 시드 묶음(봉인 전 평문)

/// 라벨 → 시드. 봉인하기 전의 평문이다 — 디스크에 쓰지 않는다. 쓴 뒤 시드 배열을 `wipe`로 덮는 것은 부른 쪽 몫이다.
typealias SecretMap = [String: [UInt8]]

/// `{"라벨":"Base64"}` JSON.
func encodeSecrets(_ m: SecretMap) -> Data {
    // 문자열 사전은 인코딩이 실패하지 않는다. 실패를 빈 데이터로 덮으면 빈 묶음이 봉인돼 시드를 전부 잃으므로 멈추게 둔다.
    try! JSONEncoder().encode(m.mapValues { Data($0) })  // Data의 기본 인코딩이 Base64
}

func decodeSecrets(_ d: Data) throws -> SecretMap {
    guard let m = try? JSONDecoder().decode([String: Data].self, from: d) else { throw StoreError.corrupt }
    return m.mapValues { [UInt8]($0) }
}

// MARK: - 병합·라벨 찾기

/// 들어오는 항목을 기존 목록에 합친다. 기존 항목 X와 라벨이 같거나, `uniqueID`가 (둘 다 있고) 같거나,
/// issuer·name·시드가 모두 같으면 중복이다.
/// 중복이면 겹치는 기존 항목마다 `confirmOverwrite(X.label)`로 묻는다. 모두 승낙하면 그 항목들을 지우고 들어온 항목을
/// 새 라벨로 맨 끝에 붙이고(replaced), 하나라도 거절하면 아무것도 바꾸지 않고 건너뛴다(skipped).
/// 겹침이 둘 이상이어도 라벨이 유일하게 남는다. 들어오는 항목은 차례로 판정하므로 앞서 붙은 항목과도 겹칠 수 있다.
func mergeEntries(existing: [StoredEntry], secrets: SecretMap, incoming: [(label: String, entry: ImportedEntry)],
                  confirmOverwrite: (String) -> Bool) -> (entries: [StoredEntry], secrets: SecretMap, added: Int, replaced: Int, skipped: Int) {
    var entries = existing, secrets = secrets
    var added = 0, replaced = 0, skipped = 0
    for (label, e) in incoming {
        let clashes = entries.filter {
            $0.label == label
                || ($0.uniqueID != nil && $0.uniqueID == e.uniqueID)
                || ($0.issuer == e.issuer && $0.name == e.name && secrets[$0.label] == e.secret)
        }
        if clashes.isEmpty {
            added += 1
        } else if clashes.allSatisfy({ confirmOverwrite($0.label) }) {
            let gone = Set(clashes.map(\.label))
            entries.removeAll { gone.contains($0.label) }
            for l in gone { secrets[l] = nil }
            replaced += 1
        } else {
            skipped += 1
            continue
        }
        entries.append(StoredEntry(label: label, issuer: e.issuer, name: e.name, algorithm: e.algorithm,
                                   digits: e.digits, period: e.period, uniqueID: e.uniqueID))
        secrets[label] = e.secret
    }
    return (entries, secrets, added, replaced, skipped)
}

/// 정확히 일치하면 그 항목, 아니면 대소문자를 무시하고 하나만 일치할 때 그 항목.
/// 대소문자만 다른 항목이 둘 이상 걸리면 고르지 않는다(발급할 계정을 추측하지 않는다).
func resolveLabel(_ query: String, in entries: [StoredEntry]) throws -> StoredEntry {
    guard !entries.isEmpty else { throw StoreError.noEntries }
    if let exact = entries.first(where: { $0.label == query }) { return exact }
    let folded = entries.filter { $0.label.lowercased() == query.lowercased() }
    if folded.count == 1 { return folded[0] }
    throw StoreError.unknownLabel(query, available: entries.map(\.label))
}
