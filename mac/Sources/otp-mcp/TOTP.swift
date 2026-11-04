import CryptoKit
import Foundation

enum OTPAlgorithm: String, Codable {
    case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512"
}

enum OTPError: Error, CustomStringConvertible {
    case invalidBase32
    case unsupported(String)
    case invalidURI(String)
    case qrNotFound(String)

    var description: String {
        switch self {
        case .invalidBase32: return "Base32 형식이 아닌 비밀키입니다"
        case .unsupported(let x): return "지원하지 않는 형식입니다: \(x)"
        case .invalidURI(let x): return "OTP 주소를 해석할 수 없습니다: \(x)"
        case .qrNotFound(let path): return "QR을 찾지 못했습니다: \(path) — 더 가까이, 정면에서 다시 찍어 주세요"
        }
    }
}

/// Base32(RFC 4648) 해독. 소문자·공백(줄바꿈 포함)·`=`은 무시하고, 그 밖에 알파벳 밖의 문자는 거부한다.
/// 바이트 단위로 훑어 ASCII만 대문자로 바꾼다(`uppercased()`는 "ß"→"SS"처럼 알파벳 문자를 만들어 낸다).
/// 에러에는 입력을 싣지 않는다(시드 노출 금지).
func base32Decode(_ text: String) throws -> [UInt8] {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
    var out: [UInt8] = []
    var buffer = 0, bits = 0
    for var b in text.utf8 {
        if b == UInt8(ascii: "=") || b == UInt8(ascii: " ") || (0x09...0x0D).contains(b) { continue }
        if (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(b) { b -= 0x20 }
        guard let v = alphabet.firstIndex(of: b) else { throw OTPError.invalidBase32 }
        buffer = (buffer << 5) | v
        bits += 5
        if bits >= 8 {
            bits -= 8
            out.append(UInt8(truncatingIfNeeded: buffer >> bits))
            buffer &= (1 << bits) - 1
        }
    }
    return out
}

/// RFC 6238(TOTP) = RFC 4226(HOTP)에 카운터 `unixTime / period`를 넣은 것.
func totp(secret: [UInt8], unixTime: Int64, algorithm: OTPAlgorithm, digits: Int, period: Int) -> String {
    let counter = UInt64(unixTime / Int64(period))
    let message = Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: counter >> ($0 * 8)) })  // 빅엔디안 8바이트
    let key = SymmetricKey(data: secret)
    let mac: [UInt8]
    switch algorithm {
    case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
    case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
    case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
    }
    // 동적 절단: 마지막 바이트의 아래 4비트가 오프셋, 거기서 31비트를 뽑는다.
    let offset = Int(mac[mac.count - 1] & 0x0F)
    let truncated = (Int(mac[offset] & 0x7F) << 24) | (Int(mac[offset + 1]) << 16)
                  | (Int(mac[offset + 2]) << 8) | Int(mac[offset + 3])
    let value = String(truncated % (0..<digits).reduce(1) { acc, _ in acc * 10 })
    return String(repeating: "0", count: max(0, digits - value.count)) + value
}

struct IssuedCode: Equatable {
    let code: String
    let remainingSeconds: Int
}

/// 코드를 발급한다. 남은 시간이 10초 미만이면 코드를 쓰는 쪽(LLM 왕복 포함)이 입력하기 전에 만료될 수 있으므로
/// 다음 주기 시작까지 `sleep`한 뒤 그 주기의 코드를 돌려준다(남은 시간은 `period`). 남은 시간은 소수 초로 계산하고,
/// 돌려주는 값은 내림한 정수라 실제보다 길게 알리지 않는다.
func issueCode(secret: [UInt8], algorithm: OTPAlgorithm, digits: Int, period: Int, now: Double, sleep: (Double) -> Void) -> IssuedCode {
    let remaining = Double(period) - now.truncatingRemainder(dividingBy: Double(period))
    let mustWait = remaining < 10
    if mustWait { sleep(remaining) }
    let at = Int64(mustWait ? now + remaining : now)  // 기다렸다면 다음 주기 시작 시각(now + remaining은 period의 배수라 정확하다)
    return IssuedCode(code: totp(secret: secret, unixTime: at, algorithm: algorithm, digits: digits, period: period),
                      remainingSeconds: mustWait ? period : Int(remaining))
}
