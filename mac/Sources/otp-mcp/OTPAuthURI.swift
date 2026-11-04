import Foundation

// 가져오기 주소 해석: 서비스 등록 QR(`otpauth://totp/…`)과 Google Authenticator 내보내기 QR(`otpauth-migration://offline?data=…`).
// 오류 문구에는 필드 이름과 문제 값만 싣는다. 주소 전체나 시드는 넣지 않는다.

/// 가져온 계정 한 개. 시드를 담고 있으니 출력하거나 기록하지 않는다.
struct ImportedEntry {
    var issuer: String
    var name: String
    var algorithm: OTPAlgorithm
    var digits: Int
    var period: Int
    var secret: [UInt8]
    var uniqueID: String?
}

/// 가져오지 않고 건너뛴 항목과 사유(사용자에게 보여 주는 용도).
struct SkippedEntry: Equatable {
    var issuer: String
    var name: String
    var reason: String
}

// ponytail: 경로나 쿼리 한 곳에 날것의 한글·공백과 `%XX`가 섞이면 Foundation이 그곳의 `%`까지 다시 인코딩해 `%20`이 그대로 남는다.
// 시드는 오염되지 않고(남은 `%`를 Base32·Base64 해독이 거부한다) 레이블만 어긋난다. 필요해지면 날것 문자만 먼저 인코딩해서 넘긴다.
/// 스킴이 맞는 주소만 `URLComponents`로 돌려준다. 퍼센트 인코딩은 `path`·`queryItems`가 풀어 준다.
private func components(of uri: String, scheme: String) throws -> URLComponents {
    guard let c = URLComponents(string: uri), c.scheme?.lowercased() == scheme else {
        throw OTPError.invalidURI("\(scheme):// 주소가 아님")
    }
    return c
}

/// 프로토버프 int32 값(음수는 64비트로 부호 확장돼 실린다)을 Int로.
private func int32(_ v: UInt64) -> Int { Int(Int32(truncatingIfNeeded: v)) }

// MARK: - otpauth://totp/<발급자>:<이름>?secret=…&issuer=…&algorithm=…&digits=…&period=…

func parseOTPAuthURI(_ uri: String) throws -> ImportedEntry {
    let c = try components(of: uri, scheme: "otpauth")
    switch c.host?.lowercased() {
    case "totp": break
    case "hotp": throw OTPError.unsupported("HOTP")
    default: throw OTPError.invalidURI("type=\(c.host ?? "")")
    }
    let query = c.queryItems ?? []
    func param(_ key: String) -> String? { query.first { $0.name == key }?.value }

    // 레이블은 "발급자:이름" 또는 "이름"이다. issuer 매개변수가 있으면 그 값이 우선한다.
    let label = String(c.path.drop(while: { $0 == "/" }))
    var issuer = "", name = label
    if let colon = label.firstIndex(of: ":") {
        issuer = String(label[..<colon])
        name = String(label[label.index(after: colon)...])
    }
    if let p = param("issuer"), !p.isEmpty { issuer = p }

    var algorithm = OTPAlgorithm.sha1
    if let a = param("algorithm") {
        guard let parsed = OTPAlgorithm(rawValue: a.uppercased()) else { throw OTPError.unsupported(a) }
        algorithm = parsed
    }
    var digits = 6
    if let d = param("digits") {
        guard let n = Int(d), (6...8).contains(n) else { throw OTPError.invalidURI("digits=\(d)") }
        digits = n
    }
    var period = 30  // `totp`가 period로 나누므로 1 이상이어야 한다.
    if let p = param("period") {
        guard let n = Int(p), n >= 1 else { throw OTPError.invalidURI("period=\(p)") }
        period = n
    }
    let secret = try base32Decode(param("secret") ?? "")
    guard !secret.isEmpty else { throw OTPError.invalidURI("secret 없음") }

    return ImportedEntry(issuer: issuer, name: name, algorithm: algorithm, digits: digits, period: period,
                         secret: secret, uniqueID: nil)
}

// MARK: - otpauth-migration://offline?data=<Base64(MigrationPayload)>  (설계 부록 A)

/// 프로토버프 와이어 포맷 리더. 필요한 것만 읽는다: varint(0)와 길이 구분(2).
/// 고정 64(1)·32(5)는 건너뛰고, 그 밖의 와이어 타입이나 잘린 데이터는 오류다.
private struct ProtoReader {
    enum Value { case varint(UInt64), bytes([UInt8]) }

    private let data: [UInt8]
    private var pos = 0

    init(_ data: [UInt8]) { self.data = data }

    private static var malformed: OTPError { .invalidURI("data 구조 오류") }

    private mutating func varint() throws -> UInt64 {
        var result: UInt64 = 0
        for shift in stride(from: 0, to: 64, by: 7) {  // 최대 10바이트
            guard pos < data.count else { throw Self.malformed }
            let byte = data[pos]
            pos += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
        }
        throw Self.malformed
    }

    private mutating func skip(_ count: Int) throws {
        guard count <= data.count - pos else { throw Self.malformed }
        pos += count
    }

    /// 다음 (필드 번호, 값). 끝이면 nil. 고정 폭 필드(1·5)는 값을 돌려주지 않고 건너뛴다.
    mutating func next() throws -> (field: Int, value: Value)? {
        while pos < data.count {
            let tag = try varint()
            let field = Int(truncatingIfNeeded: tag >> 3)
            switch tag & 7 {
            case 0:
                let v = try varint()
                return (field, .varint(v))
            case 2:
                let length = try varint()
                guard length <= UInt64(data.count - pos) else { throw Self.malformed }
                let start = pos
                pos += Int(length)
                return (field, .bytes(Array(data[start..<pos])))
            case 1: try skip(8)
            case 5: try skip(4)
            default: throw Self.malformed
            }
        }
        return nil
    }
}

private enum Parsed {
    case entry(ImportedEntry)
    case skipped(SkippedEntry)
}

/// OtpParameters 한 개: 1 secret, 2 name, 3 issuer, 4 algorithm, 5 digits, 6 type, 7 counter, 8 unique_id.
/// 가져올 수 없는 항목은 오류가 아니라 사유와 함께 건너뛴다(한 항목 때문에 묶음 전체를 버리지 않는다).
private func parseOtpParameters(_ bytes: [UInt8]) throws -> Parsed {
    var secret: [UInt8] = [], name = "", issuer = "", uniqueID: String?
    var algorithm = 0, digits = 0, type = 0
    var reader = ProtoReader(bytes)
    while let (field, value) = try reader.next() {
        switch (field, value) {
        case (1, .bytes(let b)): secret = b
        case (2, .bytes(let b)): name = String(decoding: b, as: UTF8.self)
        case (3, .bytes(let b)): issuer = String(decoding: b, as: UTF8.self)
        case (4, .varint(let v)): algorithm = int32(v)
        case (5, .varint(let v)): digits = int32(v)
        case (6, .varint(let v)): type = int32(v)
        case (8, .bytes(let b)): uniqueID = b.isEmpty ? nil : String(decoding: b, as: UTF8.self)  // 빈 값은 중복 판정에 쓰지 않는다.
        default: break  // counter(HOTP 전용)와 모르는 필드
        }
    }
    func skip(_ reason: String) -> Parsed { .skipped(SkippedEntry(issuer: issuer, name: name, reason: reason)) }

    switch type {  // type을 먼저 본다.
    case 2: break
    case 1: return skip("HOTP")
    case 0: return skip("형식 미지정")
    default: return skip("알 수 없는 형식 \(type)")
    }
    let algo: OTPAlgorithm
    switch algorithm {
    case 1: algo = .sha1
    case 2: algo = .sha256
    case 3: algo = .sha512
    case 4: return skip("MD5")
    case 0: return skip("알고리즘 미지정")
    default: return skip("알 수 없는 알고리즘 \(algorithm)")
    }
    let digitCount: Int
    switch digits {
    case 0, 1: digitCount = 6
    case 2: digitCount = 8
    case 3: digitCount = 7
    default: return skip("알 수 없는 자릿수 \(digits)")
    }
    guard !secret.isEmpty else { return skip("시드 없음") }
    return .entry(ImportedEntry(issuer: issuer, name: name, algorithm: algo, digits: digitCount, period: 30,
                                secret: secret, uniqueID: uniqueID))
}

func parseMigrationURI(_ uri: String) throws -> (entries: [ImportedEntry], skipped: [SkippedEntry]) {
    let c = try components(of: uri, scheme: "otpauth-migration")
    guard var b64 = c.queryItems?.first(where: { $0.name == "data" })?.value else { throw OTPError.invalidURI("data 없음") }
    // 표준 Base64다(URL-safe 아님). 패딩이 빠졌거나 어긋나 있으면 다시 맞춘다.
    while b64.hasSuffix("=") { b64.removeLast() }
    b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
    guard let raw = Data(base64Encoded: b64) else { throw OTPError.invalidURI("data 해독 실패") }

    // MigrationPayload: 1 OtpParameters(반복), 2 version, 3 batch_size, 4 batch_index. 5 batch_id 등은 읽지 않는다.
    var version = 0, batchSize = 0, batchIndex = 0
    var parameters: [[UInt8]] = []
    var reader = ProtoReader(Array(raw))
    while let (field, value) = try reader.next() {
        switch (field, value) {
        case (1, .bytes(let b)): parameters.append(b)
        case (2, .varint(let v)): version = int32(v)
        case (3, .varint(let v)): batchSize = int32(v)
        case (4, .varint(let v)): batchIndex = int32(v)
        default: break
        }
    }
    guard (1...2).contains(version) else { throw OTPError.invalidURI("version \(version)") }
    guard batchSize >= 1 else { throw OTPError.invalidURI("batch_size \(batchSize)") }
    guard (0..<batchSize).contains(batchIndex) else { throw OTPError.invalidURI("batch_index \(batchIndex)/\(batchSize)") }

    var entries: [ImportedEntry] = [], skipped: [SkippedEntry] = []
    for p in parameters {
        switch try parseOtpParameters(p) {
        case .entry(let e): entries.append(e)
        case .skipped(let s): skipped.append(s)
        }
    }
    return (entries, skipped)
}

// MARK: - 스킴으로 나누기

/// `otpauth://`는 항목 1개, `otpauth-migration://`은 묶음을 돌려준다. 앞뒤 공백·줄바꿈은 무시한다.
func parseAnyURI(_ uri: String) throws -> (entries: [ImportedEntry], skipped: [SkippedEntry]) {
    let text = uri.trimmingCharacters(in: .whitespacesAndNewlines)
    switch URLComponents(string: text)?.scheme?.lowercased() {
    case "otpauth": return (entries: [try parseOTPAuthURI(text)], skipped: [])
    case "otpauth-migration": return try parseMigrationURI(text)
    default: throw OTPError.invalidURI("otpauth:// 또는 otpauth-migration:// 주소가 아님")  // 입력은 시드일 수 있어 싣지 않는다.
    }
}
