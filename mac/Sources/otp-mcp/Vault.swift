import CryptoKit
import Foundation
import LocalAuthentication
import Security

// 시드 묶음을 Secure Enclave(SE) 키의 공개키로 봉인하고, 열 때마다 사용자 승인(Touch ID/암호)을 받는다.
// 봉인은 공개키만으로 되므로 승인이 필요 없고(가져오기), 여는 것은 SE 안의 개인키만 할 수 있어 승인이 필요하다(발급).
// 오류 문구에는 시드·키 데이터·복호 결과를 싣지 않는다(시스템 오류 설명만).

struct SealedSecrets: Codable, Equatable {
    var ephemeralPublicKey: String  // Base64(x963) — 봉인할 때 한 번만 쓴 일회용 공개키
    var box: String                 // Base64(AES-GCM combined)
}

enum VaultError: Error, CustomStringConvertible {
    case denied(String)
    case timeout
    case corrupt

    var description: String {
        switch self {
        case .denied(let why): return "승인 또는 키 사용에 실패했습니다(\(why))"
        case .timeout: return "승인 대기 시간(60초)이 지났습니다"
        case .corrupt: return "봉인된 데이터가 손상되었습니다"
        }
    }
}

extension VaultError {
    /// 승인 창의 결과가 아닌 오류(사용자 취소·인증 실패, 이 맥에서 쓸 수 없는 키 등)를 `.denied`로 바꾼다.
    /// 사유는 시스템이 만든 문구뿐이라 비밀값이 없다: 사람이 읽는 설명과, 원인(오류 종류·코드)이 보이는 `String(describing:)`을 함께 싣는다.
    static func denied(because error: Error) -> VaultError {
        .denied("\(error.localizedDescription) — \(String(describing: error))")
    }
}

/// 봉인과 해제가 같은 키를 만들도록 한곳에서 유도한다: ECDH 비밀 → HKDF-SHA256(솔트 = 일회용 공개키).
private func sealingKey(_ shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral.x963Representation,
                                   sharedInfo: Data("otp-mcp seal v1".utf8), outputByteCount: 32)
}

func sealSecrets(_ plaintext: Data, to recipient: P256.KeyAgreement.PublicKey) throws -> SealedSecrets {
    let ephemeral = P256.KeyAgreement.PrivateKey()  // 봉인마다 새로 만들고 버린다
    let key = sealingKey(try ephemeral.sharedSecretFromKeyAgreement(with: recipient), ephemeral: ephemeral.publicKey)
    guard let combined = try AES.GCM.seal(plaintext, using: key).combined else { throw VaultError.corrupt }
    return SealedSecrets(ephemeralPublicKey: ephemeral.publicKey.x963Representation.base64EncodedString(),
                         box: combined.base64EncodedString())
}

/// `agree`가 던지는 오류(승인 거절 등)는 그대로 올리고, 형식이 깨졌거나 인증 태그가 안 맞으면 `.corrupt`.
func openSecrets(_ sealed: SealedSecrets, agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> Data {
    guard let pubData = Data(base64Encoded: sealed.ephemeralPublicKey),
          let boxData = Data(base64Encoded: sealed.box),
          let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: pubData) else { throw VaultError.corrupt }
    let key = sealingKey(try agree(ephemeral), ephemeral: ephemeral)
    do { return try AES.GCM.open(AES.GCM.SealedBox(combined: boxData), using: key) } catch { throw VaultError.corrupt }
}

/// `body`를 전역 큐에서 돌리고 `seconds`만 기다린다. 넘기면 `cancel()`을 부르고 `.timeout`을 던진다(body는 취소되길 기다리다 버려진다).
/// body의 오류는 그대로 다시 던진다.
/// 한계(받아들임): 시간 초과 뒤 늦게 끝난 결과는 제네릭 상자(`result`)에 담겼다가 그대로 해제된다 — `T`를 몰라 지우지 못한다(설계 §5.3 최선 노력).
func withApprovalTimeout<T>(seconds: Double, cancel: @escaping () -> Void, _ body: @escaping () throws -> T) throws -> T {
    var result: Result<T, Error>?  // 세마포어가 쓰기→읽기 순서를 보장한다. 시간 초과 뒤의 늦은 쓰기는 아무도 읽지 않는다.
    let done = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        result = Result { try body() }
        done.signal()
    }
    if done.wait(timeout: .now() + seconds) == .timedOut {
        cancel()
        throw VaultError.timeout
    }
    return try result!.get()
}

/// SE 안에 새 키를 만들고 그 `dataRepresentation`(이 기기의 SE에서만 쓸 수 있는 불투명한 조각)을 돌려준다.
/// 사용할 때마다 사용자 확인(Touch ID/암호)이 필요하다.
func createEnclaveKey() throws -> Data {
    let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                 [.privateKeyUsage, .userPresence], nil)!  // 상수 조합이라 실패하지 않는다
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access).dataRepresentation
}

/// 공개키만 꺼낸다. 개인키를 쓰지 않으니 승인 창이 뜨지 않아야 한다(R1에서 `vault-check`의 1/4 전에 창이 뜨면 어긋난 것).
func enclavePublicKey(_ keyData: Data) throws -> P256.KeyAgreement.PublicKey {
    try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData).publicKey
}

/// 승인(Touch ID/암호)을 받고 연다. 호출마다 새 `LAContext`를 쓴다 — 재사용하면 앞선 승인이 이어진다(M1).
/// 시간 초과·손상은 `VaultError`로 그대로, 그 밖의 오류(사용자 취소·인증 실패, 이 맥에서 쓸 수 없는 키 등)는 `.denied(because:)`로 바꾼다.
func unsealWithApproval(_ sealed: SealedSecrets, keyData: Data, reason: String, timeoutSeconds: Double = 60) throws -> Data {
    let ctx = LAContext()
    ctx.localizedReason = reason
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData, authenticationContext: ctx)
        return try withApprovalTimeout(seconds: timeoutSeconds, cancel: { ctx.invalidate() }) {
            try openSecrets(sealed) { try key.sharedSecretFromKeyAgreement(with: $0) }
        }
    } catch let e as VaultError {
        throw e
    } catch {
        throw VaultError.denied(because: error)
    }
}

/// 가져온 비밀값을 쓴 뒤 메모리를 0으로 덮는다. 이 변수의 저장소만 지우며, 이미 만들어진 사본까지는 지우지 못한다.
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { if let p = $0.baseAddress { memset_s(p, $0.count, 0, $0.count) } }
}

func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { if let p = $0.baseAddress { memset_s(p, $0.count, 0, $0.count) } }
}

/// `vault-check [--once]` — 1단계 관문(R1·R2)의 수동 확인. 임시 SE 키를 메모리에만 만들어 `"vault-check"`를 봉인하고,
/// 승인 창을 차례로 띄워 결과를 기대와 맞춘다(저장 파일·키체인에는 아무것도 쓰지 않는다). 모두 기대대로면 0.
func runVaultCheck(once: Bool) -> Int32 {
    let steps: [(reason: String, timeout: Double, expected: String)] = [
        ("vault-check 1/4 · 승인해 주세요", 60, "성공"),
        ("vault-check 2/4 · 다시 승인해 주세요", 60, "성공"),
        ("vault-check 3/4 · 취소를 눌러 주세요", 60, "denied"),
        ("vault-check 4/4 · 10초 동안 그대로 두세요", 10, "timeout"),
    ]
    let probe = Data("vault-check".utf8)
    let keyData: Data, sealed: SealedSecrets
    do {
        keyData = try createEnclaveKey()
        sealed = try sealSecrets(probe, to: try enclavePublicKey(keyData))
    } catch {
        print("vault-check: 준비 실패 — \(error)")
        return 1
    }
    let run = once ? Array(steps.prefix(1)) : steps
    var matched = 0
    for (i, step) in run.enumerated() {
        var actual = "성공", detail = ""
        do {
            var opened = try unsealWithApproval(sealed, keyData: keyData, reason: step.reason, timeoutSeconds: step.timeout)
            if opened != probe { actual = "불일치" }  // 승인은 됐는데 봉인한 값이 아니다
            wipe(&opened)
        } catch {
            switch error {
            case VaultError.timeout: actual = "timeout"  // 문구의 «60초»는 고정값이라 4번(10초)에는 맞지 않아 싣지 않는다
            case VaultError.denied: actual = "denied"; detail = " — \(error)"
            default: actual = "오류"; detail = " — \(error)"
            }
        }
        let ok = actual == step.expected
        matched += ok ? 1 : 0
        print("\(i + 1)/4 \(actual)\(detail)\(ok ? "" : " ← 기대는 \(step.expected)")")
    }
    let all = matched == run.count
    print(all ? "vault-check: 기대대로 \(matched)/\(run.count)" : "vault-check: 기대와 다름 (\(matched)/\(run.count) 일치)")
    return all ? 0 : 1
}
