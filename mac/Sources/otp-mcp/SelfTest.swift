import CoreGraphics
import CryptoKit
import Foundation

// XCTest 없이(CommandLineTools만 있는 환경) 돌리는 자체 시험.
// 실행: swift run otp-mcp selftest ../shared/testvectors.json

/// shared/testvectors.json과 1:1로 맞춘 시험 데이터.
struct Vectors: Decodable {
    struct RFC: Decodable {
        let secret: String
        let algorithm: String
        let time: Int64
        let digits: Int
        let code: String
    }
    struct Expected: Decodable {
        let issuer: String
        let name: String
        let algorithm: String
        let digits: Int
        let period: Int
        let uniqueID: String?
        let secret: String?
        let code: String
        let uri: String?
    }
    struct Skipped: Decodable {
        let issuer: String
        let name: String
        let reason: String
    }
    struct Migration: Decodable {
        let uri: String
        let time: Int64
        let entries: [Expected]
        let skipped: [Skipped]
    }
    struct MigrationBad: Decodable {
        let version3: String
        let batchIndexOutOfRange: String
    }
    struct OTPAuth: Decodable {
        let time: Int64
        let valid: [Expected]
        let invalid: [String]
    }

    let rfc6238: [RFC]
    let migration: Migration
    let migrationBad: MigrationBad
    let otpauth: OTPAuth
}

struct Check {
    let name: String
    let run: (Vectors) throws -> Void
}

struct CheckFailure: Error, CustomStringConvertible {
    let description: String
}

func expect(_ ok: Bool, _ message: @autoclosure () -> String) throws {
    if !ok { throw CheckFailure(description: message()) }
}

/// 실제 저장소(`~/Library/…`)를 건드리지 않도록 `OTP_MCP_HOME`을 임시 폴더로 바꿔 `body`를 돈다.
/// 끝나면(실패해도) 환경 변수를 원래대로 되돌리고 폴더를 지운다.
func withTempHome(_ body: (URL) throws -> Void) rethrows {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("otp-mcp-test-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let previous = getenv("OTP_MCP_HOME").map { String(cString: $0) }  // 겹쳐 불려도 바깥 값이 실제 저장소로 풀리지 않게
    setenv("OTP_MCP_HOME", dir.path, 1)
    defer {
        if let previous { setenv("OTP_MCP_HOME", previous, 1) } else { unsetenv("OTP_MCP_HOME") }
        try? FileManager.default.removeItem(at: dir)
    }
    try body(dir)
}

/// 200×200 흰색 PNG — QR이 없는 사진을 흉내 낸다.
func writeBlankPNG(to url: URL) throws {
    let ctx = CGContext(data: nil, width: 200, height: 200, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!  // 고정 인자라 실패하지 않는다
    ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
    ctx.fill(CGRect(x: 0, y: 0, width: 200, height: 200))
    try writePNG(ctx.makeImage()!, to: url)
}

/// 응답 한 줄(JSON 객체)을 사전으로 푼다.
func json(_ line: String) throws -> [String: Any] {
    guard let object = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
        throw CheckFailure(description: "JSON 객체가 아님: \(line)")
    }
    return object
}

/// `tools/call`을 보내고 `result.content[0].text`와 `result.isError`를 돌려준다. `params`는 JSON 객체 글자.
func toolText(_ h: MCPHandler, _ params: String) throws -> (text: String, isError: Bool) {
    guard let reply = h.handle(#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":"# + params + "}") else {
        throw CheckFailure(description: "tools/call에 응답이 없음")
    }
    let r = try json(reply)
    guard let result = r["result"] as? [String: Any], let content = (result["content"] as? [[String: Any]])?.first,
          content["type"] as? String == "text", let text = content["text"] as? String,
          let isError = result["isError"] as? Bool else { throw CheckFailure(description: "tools/call 응답 모양: \(reply)") }
    return (text, isError)
}

/// 이후 Task가 항목을 덧붙인다.
var allChecks: [Check] = [
    Check(name: "rfc6238") { v in
        for r in v.rfc6238 {
            let c = totp(secret: try base32Decode(r.secret), unixTime: r.time,
                         algorithm: OTPAlgorithm(rawValue: r.algorithm)!, digits: r.digits, period: 30)
            try expect(c == r.code, "\(r.algorithm) t=\(r.time): \(c) != \(r.code)")
        }
    },
    Check(name: "digits-6-7") { _ in
        let s = try base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        try expect(totp(secret: s, unixTime: 59, algorithm: .sha1, digits: 6, period: 30) == "287082", "6자리")
        try expect(totp(secret: s, unixTime: 59, algorithm: .sha1, digits: 7, period: 30) == "4287082", "7자리")
    },
    Check(name: "base32-lenient") { _ in
        try expect(try base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq") == Array("12345678901234567890".utf8), "소문자·공백")
    },
    Check(name: "base32-invalid") { _ in
        do { _ = try base32Decode("ABC1"); try expect(false, "1은 Base32 문자가 아니다") } catch is OTPError {}
    },
    Check(name: "issue-wait") { _ in
        let s = try base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        func issue(_ now: Double) -> (slept: [Double], issued: IssuedCode) {
            var slept: [Double] = []
            let issued = issueCode(secret: s, algorithm: .sha1, digits: 8, period: 30, now: now, sleep: { slept.append($0) })
            return (slept, issued)
        }
        func code(_ t: Int64) -> String { totp(secret: s, unixTime: t, algorithm: .sha1, digits: 8, period: 30) }
        // 남은 시간이 10초 미만이면 소수 초까지 정확히 기다려 다음 주기 시작(60)의 코드를 받고, 남은 시간은 period로 알린다.
        var r = issue(58)
        try expect(r.slept == [2] && r.issued.remainingSeconds == 30 && r.issued.code == code(60), "남은 2초면 다음 주기")
        r = issue(52.5)
        try expect(r.slept == [7.5] && r.issued.remainingSeconds == 30 && r.issued.code == code(60), "남은 7.5초(소수)도 다음 주기")
        // 실제 시각 크기(약 1.7e9초)의 소수 초에서도 `now + remaining`이 다음 주기 시작(…070)에 정확히 떨어진다.
        r = issue(1_700_000_065.25)
        try expect(r.slept == [4.75] && r.issued.remainingSeconds == 30 && r.issued.code == code(1_700_000_070), "실제 시각 크기에서 다음 주기")
        // 10초 이상이면 기다리지 않고 지금 주기의 코드. 경계는 «정확히 10초 = 대기 없음», 남은 시간은 내림한 정수.
        r = issue(40)
        try expect(r.slept.isEmpty && r.issued.remainingSeconds == 20 && r.issued.code == code(59), "남은 20초면 바로")
        r = issue(50)
        try expect(r.slept.isEmpty && r.issued.remainingSeconds == 10 && r.issued.code == code(59), "남은 정확히 10초면 바로")
        r = issue(41.5)
        try expect(r.slept.isEmpty && r.issued.remainingSeconds == 18, "남은 18.5초는 18로 내림")
    },
    Check(name: "otpauth-valid") { v in
        for e in v.otpauth.valid {
            let p = try parseOTPAuthURI(e.uri!)
            try expect(p.issuer == e.issuer && p.name == e.name && p.algorithm.rawValue == e.algorithm
                       && p.digits == e.digits && p.period == e.period, "필드: \(e.uri!)")
            try expect(totp(secret: p.secret, unixTime: v.otpauth.time, algorithm: p.algorithm,
                            digits: p.digits, period: p.period) == e.code, "코드: \(e.name)")
        }
    },
    Check(name: "otpauth-invalid") { v in
        for uri in v.otpauth.invalid {
            do {
                _ = try parseOTPAuthURI(uri)
                try expect(false, "거부해야 함: \(uri)")
            } catch let e as OTPError {
                // 오류 문구에는 시드도, 주소에 든 `secret=`도 실리면 안 된다(필드 이름과 문제 값만).
                let text = String(describing: e)
                try expect(!text.contains("N52HALLNMNYC2ZTBNNSS243FMVSC2QJR") && !text.contains("secret="),
                           "오류 문구에 시드 또는 secret= 노출: \(text)")
            }
        }
    },
    Check(name: "migration-synthetic") { v in
        let r = try parseMigrationURI(v.migration.uri)
        try expect(r.entries.count == 2 && r.skipped.count == 2, "2개 가져오고 2개 건너뜀")
        for (p, e) in zip(r.entries, v.migration.entries) {
            try expect(p.issuer == e.issuer && p.name == e.name && p.algorithm.rawValue == e.algorithm
                       && p.digits == e.digits && p.period == 30 && p.uniqueID == e.uniqueID, "필드: \(e.name)")
            try expect(p.secret == (try base32Decode(e.secret!)), "시드: \(e.name)")
            try expect(totp(secret: p.secret, unixTime: v.migration.time, algorithm: p.algorithm,
                            digits: p.digits, period: 30) == e.code, "코드: \(e.name)")
        }
        try expect(r.skipped == v.migration.skipped.map { SkippedEntry(issuer: $0.issuer, name: $0.name, reason: $0.reason) }, "건너뛴 항목·사유")
    },
    Check(name: "migration-bad") { v in
        for uri in [v.migrationBad.version3, v.migrationBad.batchIndexOutOfRange] {
            do {
                _ = try parseMigrationURI(uri)
                try expect(false, "거부해야 함")
            } catch let e as OTPError {
                // 오류 문구에는 `data=`(시드가 든 Base64가 붙은 주소)가 실리면 안 된다.
                let text = String(describing: e)
                try expect(!text.contains("data="), "오류 문구에 주소 노출: \(text)")
            }
        }
    },
    // 승인(Secure Enclave)이 필요 없는 소프트웨어 키로 봉인 계산만 시험한다. 실제 승인은 `vault-check`가 본다.
    Check(name: "seal-roundtrip") { _ in
        let key = P256.KeyAgreement.PrivateKey()
        let sealed = try sealSecrets(Data("비밀".utf8), to: key.publicKey)
        var opened = try openSecrets(sealed) { try key.sharedSecretFromKeyAgreement(with: $0) }
        try expect(opened == Data("비밀".utf8), "왕복")
        var bad = sealed
        var raw = Data(base64Encoded: sealed.box)!; raw[raw.count - 1] ^= 0xFF; bad.box = raw.base64EncodedString()
        // `catch {}`로 두면 `expect(false)`의 실패까지 삼켜 변조를 못 잡아도 통과한다 → corrupt만 받는다.
        do { _ = try openSecrets(bad) { try key.sharedSecretFromKeyAgreement(with: $0) }; try expect(false, "변조 감지") } catch VaultError.corrupt {}
        // 승인 거절 같은 agree의 오류는 손상으로 둔갑하지 않고 그대로 올라와야 unsealWithApproval이 denied로 가른다.
        struct Refused: Error {}
        do { _ = try openSecrets(sealed) { _ in throw Refused() }; try expect(false, "agree 오류 전달") } catch is Refused {}
        // 그렇게 가른 거절의 문구. 승인과 무관한 키 사용 실패(다른 맥에서 온 저장소 등)도 이 길로 오므로 «거절»로 단정하지 않고,
        // 사유에는 시스템 오류 설명을 함께 실어 원인(오류 종류·코드)이 보이게 한다.
        try expect(String(describing: VaultError.denied("x")) == "승인 또는 키 사용에 실패했습니다(x)", "거절 문구")
        let why = String(describing: VaultError.denied(because: CryptoKitError.underlyingCoreCryptoError(error: -25293)))
        try expect(why.hasPrefix("승인 또는 키 사용에 실패했습니다(") && why.contains("underlyingCoreCryptoError(error: -25293)"), "사유에 오류 설명: \(why)")
        wipe(&opened)
        var bytes: [UInt8] = [1, 2, 3]
        wipe(&bytes)
        try expect(opened == Data(count: 6) && bytes == [0, 0, 0], "wipe는 제자리에서 0으로 덮는다")
    },
    // 봉인 형식 고정(KAT): 지금 코드로 한 번 봉인해 얼린 값이 앞으로도 열려야 한다. seal-roundtrip은 봉인과 해제가 함께 바뀌면 통과하므로,
    // `sealingKey`의 솔트·info·길이, AES-GCM 결합 형식, SealedSecrets 필드 이름이 바뀌어 이미 저장된 store.json이 못 열리는 사고는 이 시험만 잡는다.
    // 키와 평문은 모두 가짜다. 얼린 값은 `sealSecrets(평문, to: 고정키.publicKey)`를 한 번 돌려 JSON으로 적은 것이다.
    Check(name: "seal-kat") { _ in
        func key(_ hex: String) throws -> P256.KeyAgreement.PrivateKey {
            try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(stride(from: 0, to: hex.count, by: 2).compactMap {
                UInt8(hex.dropFirst($0).prefix(2), radix: 16)
            }))
        }
        let fixed = try key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let other = try key("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
        let frozen = try JSONDecoder().decode(SealedSecrets.self, from: Data(#"{"box":"3Qa7XrqhBxfiwtgW03HUsBZ96X9xtNt87Hmb5pD4GtJ0azBj8Gaj4ty9ZvOvvrF4PdJwAjUyH//Kkoo=","ephemeralPublicKey":"BG3a00BmKh+6w6VGnDGSAo4/gdcRDVU6NkeWBKutUXdNAq5LIy6VCaBuJAnhf2bO5A0/tJv+q/ZoLJnAOfzx75Y="}"#.utf8))
        let opened: Data
        do { opened = try openSecrets(frozen) { try fixed.sharedSecretFromKeyAgreement(with: $0) } }
        catch { throw CheckFailure(description: "얼린 봉인을 열지 못함 — 봉인 형식이 바뀌었다(기존 저장소가 열리지 않는다): \(error)") }
        try expect(opened == Data("otp-mcp seal-kat: 가짜 평문".utf8), "얼린 봉인이 알려진 평문으로 열린다")
        // 다른 키로는 인증 태그가 안 맞아 손상으로 거부된다. `catch {}`로 두면 expect(false)까지 삼키므로 corrupt만 받는다.
        do { _ = try openSecrets(frozen) { try other.sharedSecretFromKeyAgreement(with: $0) }; try expect(false, "다른 키로는 열리면 안 된다") } catch VaultError.corrupt {}
    },
    Check(name: "approval-timeout") { _ in
        var cancelled = false
        do {
            _ = try withApprovalTimeout(seconds: 0.2, cancel: { cancelled = true }) { Thread.sleep(forTimeInterval: 1); return 1 }
            try expect(false, "시간 초과여야 함")
        } catch VaultError.timeout { try expect(cancelled, "취소 호출") }
        // 제때 끝나면 값을 그대로 돌려주고 취소하지 않으며, body의 오류는 그대로 다시 던진다.
        var cancelledEarly = false
        try expect(try withApprovalTimeout(seconds: 5, cancel: { cancelledEarly = true }) { 7 } == 7 && !cancelledEarly, "제때 끝남")
        do {
            _ = try withApprovalTimeout(seconds: 5, cancel: {}) { () throws -> Int in throw VaultError.corrupt }
            try expect(false, "body 오류 전달")
        } catch VaultError.corrupt {}
    },
    // 저장 파일·병합·라벨·감사 로그. 모두 OTP_MCP_HOME을 임시 폴더로 돌려 실제 저장소를 건드리지 않는다.
    Check(name: "store-roundtrip") { _ in
        try withTempHome { home in
            try expect(storeURL().path == home.appendingPathComponent("store.json").path
                       && logURL().path == home.appendingPathComponent("otp-mcp.log").path, "OTP_MCP_HOME이 있으면 그 폴더")
            try expect((try loadStore()) == .empty, "파일 없으면 빈 저장소")
            var s = StoreFile.empty
            s.entries = [StoredEntry(label: "a", issuer: "I", name: "n", algorithm: .sha1, digits: 6, period: 30, uniqueID: nil)]
            try saveStore(s)
            try expect(try loadStore() == s, "왕복")
            let perm = try FileManager.default.attributesOfItem(atPath: storeURL().path)[.posixPermissions] as? Int
            try expect(perm == 0o600, "권한 0600")
            try Data("{깨짐".utf8).write(to: storeURL())
            do { _ = try loadStore(); try expect(false, "깨진 파일") } catch StoreError.corrupt {}
            // 깨진 파일 위에도 이름 바꾸기로 교체되고, 임시 파일이 남지 않는다
            try saveStore(s)
            try expect(try loadStore() == s && (try FileManager.default.contentsOfDirectory(atPath: home.path)) == ["store.json"], "교체·임시 파일 없음")
            // 폴더는 새로 만들 때 0700
            setenv("OTP_MCP_HOME", home.appendingPathComponent("sub/dir").path, 1)
            try saveStore(s)
            let dirPerm = try FileManager.default.attributesOfItem(atPath: otpHome().path)[.posixPermissions] as? Int
            try expect(dirPerm == 0o700, "폴더 0700")
            // 저장이 실패하면(store.json 자리에 폴더가 있어 이름을 못 바꾼다) 오류를 내고 임시 파일을 남기지 않는다
            try FileManager.default.removeItem(at: storeURL())
            try FileManager.default.createDirectory(at: storeURL(), withIntermediateDirectories: false)
            do { try saveStore(s); try expect(false, "저장 실패는 오류") } catch is POSIXError {}
            try expect(try FileManager.default.contentsOfDirectory(atPath: otpHome().path) == ["store.json"], "실패 뒤 임시 파일 없음")
            // 환경 변수가 없거나 비어 있으면 기본 위치(경로만 계산하고 파일은 건드리지 않는다)
            for value in [nil, ""] as [String?] {
                if let value { setenv("OTP_MCP_HOME", value, 1) } else { unsetenv("OTP_MCP_HOME") }
                try expect(storeURL().path.hasSuffix("/Library/Application Support/otp-mcp/store.json")
                           && logURL().path.hasSuffix("/Library/Logs/otp-mcp.log"), "기본 위치(\(value ?? "없음"))")
            }
        }
    },
    Check(name: "merge-rules") { _ in
        let a = ImportedEntry(issuer: "I", name: "n", algorithm: .sha1, digits: 6, period: 30, secret: [1, 2, 3], uniqueID: "u1")
        var asked: [String] = []
        var r = mergeEntries(existing: [], secrets: [:], incoming: [("a", a)], confirmOverwrite: { asked.append($0); return true })
        try expect(r.entries.map(\.label) == ["a"] && r.secrets["a"] == [1, 2, 3] && r.added == 1 && asked.isEmpty, "새 항목")
        var b = a; b.secret = [9]
        r = mergeEntries(existing: r.entries, secrets: r.secrets, incoming: [("b", b)], confirmOverwrite: { asked.append($0); return false })
        try expect(asked == ["a"] && r.entries.map(\.label) == ["a"] && r.secrets["a"] == [1, 2, 3] && r.skipped == 1, "같은 unique_id, 거절하면 그대로")
        asked = []
        r = mergeEntries(existing: r.entries, secrets: r.secrets, incoming: [("a", b)], confirmOverwrite: { asked.append($0); return true })
        try expect(asked == ["a"] && r.secrets["a"] == [9] && r.replaced == 1 && r.entries.count == 1, "같은 라벨, 수락하면 교체")

        // 위 세 경우가 짚지 않는 규칙들
        func imp(_ who: String, _ secret: [UInt8], uid: String? = nil) -> ImportedEntry {
            ImportedEntry(issuer: who, name: who, algorithm: .sha1, digits: 6, period: 30, secret: secret, uniqueID: uid)
        }
        func seeded(_ items: [(String, ImportedEntry)]) -> (entries: [StoredEntry], secrets: SecretMap) {
            let m = mergeEntries(existing: [], secrets: [:], incoming: items, confirmOverwrite: { _ in true })
            return (m.entries, m.secrets)
        }
        // issuer·name·시드가 같으면 unique_id가 없어도 중복. 시드만 다르면 새 항목(unique_id가 둘 다 없는 것은 «같음»이 아니다)
        let c = seeded([("c", imp("C", [1]))])
        asked = []
        r = mergeEntries(existing: c.entries, secrets: c.secrets, incoming: [("d", imp("C", [1]))], confirmOverwrite: { asked.append($0); return false })
        try expect(asked == ["c"] && r.skipped == 1 && r.entries.map(\.label) == ["c"], "issuer·name·시드가 같으면 중복")
        asked = []
        r = mergeEntries(existing: c.entries, secrets: c.secrets, incoming: [("d", imp("C", [2]))], confirmOverwrite: { asked.append($0); return true })
        try expect(asked.isEmpty && r.added == 1 && r.entries.map(\.label) == ["c", "d"], "시드가 다르면 새 항목")
        // 다른 라벨로 교체하면 옛 항목과 옛 시드는 사라진다
        let p = seeded([("p", imp("P", [1], uid: "u"))])
        asked = []
        r = mergeEntries(existing: p.entries, secrets: p.secrets, incoming: [("q", imp("Q", [2], uid: "u"))], confirmOverwrite: { asked.append($0); return true })
        try expect(asked == ["p"] && r.entries.map(\.label) == ["q"] && r.secrets == ["q": [2]] && r.replaced == 1, "다른 라벨로 교체")
        // 라벨은 유일해야 한다: 라벨이 겹치는 항목과 unique_id가 겹치는 항목이 따로 있으면 둘 다 묻고, 하나라도 거절하면 아무것도 바꾸지 않는다
        let xy = seeded([("x", imp("X", [1], uid: "ux")), ("y", imp("Y", [2], uid: "uy"))])
        asked = []
        r = mergeEntries(existing: xy.entries, secrets: xy.secrets, incoming: [("x", imp("Z", [3], uid: "uy"))], confirmOverwrite: { asked.append($0); return $0 == "x" })
        try expect(asked == ["x", "y"] && r.skipped == 1 && r.entries == xy.entries && r.secrets == xy.secrets, "하나라도 거절하면 그대로")
        asked = []
        r = mergeEntries(existing: xy.entries, secrets: xy.secrets, incoming: [("x", imp("Z", [3], uid: "uy"))], confirmOverwrite: { asked.append($0); return true })
        try expect(asked == ["x", "y"] && r.entries.map(\.label) == ["x"] && r.secrets == ["x": [3]] && r.replaced == 1, "모두 수락하면 겹친 항목을 지우고 하나로")
        // 한 번에 들어온 항목끼리도 차례로 판정한다
        r = mergeEntries(existing: [], secrets: [:], incoming: [("s", imp("S", [1])), ("s", imp("T", [2]))], confirmOverwrite: { _ in true })
        try expect(r.added == 1 && r.replaced == 1 && r.entries.map(\.label) == ["s"] && r.secrets == ["s": [2]], "같은 묶음 안의 같은 라벨")
    },
    Check(name: "resolve-label") { _ in
        func entries(_ labels: [String]) -> [StoredEntry] {
            labels.map { StoredEntry(label: $0, issuer: "", name: "", algorithm: .sha1, digits: 6, period: 30, uniqueID: nil) }
        }
        let e = entries(["github", "example-staging", "example-prod"])
        try expect(try resolveLabel("github", in: e).label == "github", "정확히 일치")
        try expect(try resolveLabel("GitHub", in: e).label == "github", "대소문자 무시")
        do { _ = try resolveLabel("example", in: e); try expect(false, "일치 없음") }
        catch StoreError.unknownLabel(_, let available) { try expect(available.count == 3, "등록 라벨 목록") }
        do { _ = try resolveLabel("x", in: []); try expect(false, "빈 저장소") } catch StoreError.noEntries {}
        // 정확히 일치가 대소문자 무시보다 먼저이고, 대소문자만 다른 둘이 걸리면 아무거나 고르지 않는다
        let both = entries(["GitHub", "github"])
        try expect(try resolveLabel("github", in: both).label == "github" && resolveLabel("GitHub", in: both).label == "GitHub", "정확히 일치가 먼저")
        do { _ = try resolveLabel("GITHUB", in: both); try expect(false, "모호하면 거부") } catch StoreError.unknownLabel {}
        // 사용자·MCP에 그대로 보이는 문구
        try expect(String(describing: StoreError.corrupt) == "저장 파일을 읽을 수 없습니다"
                   && String(describing: StoreError.noEntries) == "등록된 계정이 없습니다 — otp-mcp import로 먼저 가져오세요"
                   && String(describing: StoreError.unknownLabel("x", available: ["a", "b"])) == "'x' 라벨이 없습니다. 등록된 라벨: a, b", "오류 문구")
    },
    Check(name: "secrets-codec") { _ in
        try expect(try decodeSecrets(encodeSecrets(["a": [1, 2], "b": [255]])) == ["a": [1, 2], "b": [255]], "왕복")
        try expect(String(decoding: encodeSecrets(["a": [1, 2]]), as: UTF8.self) == #"{"a":"AQI="}"#, "{라벨: Base64} 형식")
        try expect(try decodeSecrets(encodeSecrets([:])) == [:], "빈 묶음")
        for bad in ["{깨짐", #"{"a":"***"}"#, #"{"a":[1,2]}"#, "[]"] {
            do { _ = try decodeSecrets(Data(bad.utf8)); try expect(false, "거부해야 함: \(bad)") } catch StoreError.corrupt {}
        }
    },
    Check(name: "audit-line") { _ in
        try withTempHome { _ in
            auditLog("issued", label: "github")
            let line = try String(contentsOf: logURL(), encoding: .utf8).split(separator: "\n").last.map(String.init) ?? ""
            let f = line.split(separator: "\t").map(String.init)
            try expect(f.count == 5 && f[1] == "issued" && f[2] == "github" && f[3].hasPrefix("ppid=") && f[4].hasPrefix("cwd="), "형식: \(line)")
            try expect(ISO8601DateFormatter().date(from: f[0]) != nil && f[3] == "ppid=\(getppid())"
                       && f[4] == "cwd=\(FileManager.default.currentDirectoryPath)", "값: \(line)")
            // 이어 쓰고, 라벨의 탭·줄바꿈·CR·ESC는 줄 형식을 깨거나 남지 못하며, 로그는 0600
            auditLog("import", label: "a\tb\nc\r\u{1B}[2J")
            let lines = try String(contentsOf: logURL(), encoding: .utf8).split(separator: "\n").map(String.init)
            let cells = lines.last?.split(separator: "\t") ?? []
            try expect(lines.count == 2 && lines[0] == line && cells.count == 5
                       && cells.allSatisfy { $0.unicodeScalars.allSatisfy { $0.properties.generalCategory != .control } },
                       "이어 쓰기·제어 문자: \(lines.map { $0.debugDescription })")
            let perm = try FileManager.default.attributesOfItem(atPath: logURL().path)[.posixPermissions] as? Int
            try expect(perm == 0o600, "로그 권한 0600")
        }
    },
    Check(name: "qr-roundtrip") { v in
        try withTempHome { home in
            let png = home.appendingPathComponent("t.png")
            try writeQRPNG(v.migration.uri, to: png)
            try expect(try decodeQRCodes(at: png.path) == [v.migration.uri], "QR 왕복")
        }
    },
    Check(name: "qr-none") { _ in
        try withTempHome { home in
            let png = home.appendingPathComponent("blank.png")
            try writeBlankPNG(to: png)
            do { _ = try decodeQRCodes(at: png.path); try expect(false, "QR 없음") } catch OTPError.qrNotFound {}
        }
    },
    Check(name: "approval-reason") { _ in
        try expect(approvalReason(label: "github", sessionFolder: "repo") == "github OTP 발급 · 세션 repo", "문구")
    },
    // MCP 서버: 줄 하나(JSON-RPC)를 넣고 응답 한 줄을 본다. 승인(Touch ID)이 필요한 실제 발급은 닿지 않는다 — issue를 가짜로 끼운다.
    Check(name: "mcp-handshake") { _ in
        let h = MCPHandler(listEntries: { [] }, issue: { _ in throw StoreError.noEntries })
        let ini = try json(h.handle(#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#)!)
        let r = ini["result"] as! [String: Any]
        try expect(r["protocolVersion"] as? String == "2025-06-18" && r["instructions"] as? String == mcpInstructions
                   && (r["serverInfo"] as? [String: Any])?["name"] as? String == "otp-mcp", "initialize")
        try expect(h.handle(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) == nil, "알림엔 응답 없음")
        let tl = try json(h.handle(#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)!)
        let names = ((tl["result"] as! [String: Any])["tools"] as! [[String: Any]]).map { $0["name"] as! String }
        try expect(names == ["otp_list", "otp_code"], "도구 2개")
        let nope = try json(h.handle(#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#)!)
        try expect((nope["error"] as? [String: Any])?["code"] as? Int == -32601, "없는 메서드")
        // 위가 짚지 않는 것: 도구 능력 선언·입력 스키마, ping과 문자열 id, id 없는 모르는 메서드, 깨진 줄·객체 아닌 줄·method 없는 줄·빈 줄
        try expect((r["capabilities"] as? [String: Any])?["tools"] != nil, "tools 능력 선언")
        let schema = ((tl["result"] as! [String: Any])["tools"] as! [[String: Any]])[1]["inputSchema"] as! [String: Any]
        try expect(schema["required"] as? [String] == ["label"] && schema["additionalProperties"] as? Bool == false, "otp_code 입력 스키마")
        let ping = try json(h.handle(#"{"jsonrpc":"2.0","id":"p-1","method":"ping"}"#)!)
        try expect(ping["id"] as? String == "p-1" && (ping["result"] as? [String: Any])?.isEmpty == true, "ping은 {}, id는 그대로")
        try expect(h.handle(#"{"jsonrpc":"2.0","method":"nope"}"#) == nil, "id 없으면 모르는 메서드도 알림")
        let junk = try json(h.handle("{깨짐")!)
        try expect((junk["error"] as? [String: Any])?["code"] as? Int == -32700 && junk["id"] is NSNull, "깨진 JSON")
        let batch = try json(h.handle("[1]")!)
        try expect((batch["error"] as? [String: Any])?["code"] as? Int == -32600 && batch["id"] is NSNull, "JSON 객체가 아님")
        let bare = try json(h.handle(#"{"jsonrpc":"2.0","id":5}"#)!)
        try expect((bare["error"] as? [String: Any])?["code"] as? Int == -32600 && bare["id"] as? Int == 5, "method 없음")
        try expect(h.handle("") == nil && h.handle("  ") == nil, "빈 줄은 무시")
    },
    Check(name: "mcp-tools-call") { _ in
        let e = StoredEntry(label: "github", issuer: "GitHub", name: "alice", algorithm: .sha1, digits: 6, period: 30, uniqueID: nil)
        let h = MCPHandler(listEntries: { [e] }, issue: { q in
            if q == "github" { return IssuedCode(code: "123456", remainingSeconds: 17) }
            throw StoreError.unknownLabel(q, available: ["github"]) })
        let list = try toolText(h, #"{"name":"otp_list","arguments":{}}"#)
        try expect(!list.isError && list.text == #"[{"issuer":"GitHub","label":"github","name":"alice"}]"#, "otp_list")
        let code = try toolText(h, #"{"name":"otp_code","arguments":{"label":"github"}}"#)
        try expect(!code.isError && code.text == #"{"code":"123456","remaining_seconds":17}"#, "otp_code")
        let bad = try toolText(h, #"{"name":"otp_code","arguments":{"label":"x"}}"#)
        try expect(bad.isError && bad.text.contains("github"), "없는 라벨 → 등록 라벨 안내")
        // 위가 짚지 않는 것: label 인자 없음, 없는 도구(프로토콜 오류), 오류 문구는 userMessage(for:) — localizedDescription이면 영어 일반 문구가 나온다
        try expect(try toolText(h, #"{"name":"otp_code","arguments":{}}"#).isError, "label 없음은 도구 오류")
        let unknown = try json(h.handle(#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope"}}"#)!)
        try expect((unknown["error"] as? [String: Any])?["code"] as? Int == -32602, "없는 도구")
        let broken = MCPHandler(listEntries: { throw StoreError.corrupt }, issue: { _ in throw VaultError.timeout })
        let l2 = try toolText(broken, #"{"name":"otp_list","arguments":{}}"#)
        let c2 = try toolText(broken, #"{"name":"otp_code","arguments":{"label":"github"}}"#)
        try expect(l2.isError && l2.text == String(describing: StoreError.corrupt)
                   && c2.isError && c2.text == String(describing: VaultError.timeout), "오류 문구")
        // 슬래시는 이스케이프하지 않는다 — 모델은 이 글자를 그대로 읽으므로 `a\/b`로 보이면 그 라벨로 다시 부르지 못한다
        let slash = StoredEntry(label: "a/b", issuer: "", name: "", algorithm: .sha1, digits: 6, period: 30, uniqueID: nil)
        let h3 = MCPHandler(listEntries: { [slash] }, issue: { _ in throw StoreError.noEntries })
        try expect(try toolText(h3, #"{"name":"otp_list","arguments":{}}"#).text == #"[{"issuer":"","label":"a/b","name":""}]"#, "슬래시")
    },
]

/// 항목마다 PASS/FAIL을 찍고, 실패가 하나도 없으면 0을 돌려준다.
func runSelfTests(vectorsPath: String) -> Int32 {
    let vectors: Vectors
    do {
        vectors = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: URL(fileURLWithPath: vectorsPath)))
    } catch {
        FileHandle.standardError.write(Data("시험 데이터를 읽지 못했습니다: \(vectorsPath) — \(error)\n".utf8))
        return 1
    }
    var passed = 0, failed = 0
    for check in allChecks {
        do {
            try check.run(vectors)
            print("PASS \(check.name)")
            passed += 1
        } catch {
            print("FAIL \(check.name): \(error)")
            failed += 1
        }
    }
    print("selftest: \(passed)개 통과, \(failed)개 실패")
    return failed == 0 ? 0 : 1
}
