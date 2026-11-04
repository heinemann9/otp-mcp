import Foundation

// 승인(Touch ID/암호)을 받아 봉인을 여는 흐름. 코드 발급, CLI의 가져오기·삭제가 함께 쓴다.
// 승인 요청과 결과는 감사 로그에 남기고, 코드·시드는 로그나 오류 문구에 싣지 않는다.

/// 승인 창에 보일 문구(C6): 어느 계정을 어느 세션이 요청하는지.
func approvalReason(label: String, sessionFolder: String) -> String {
    "\(label) OTP 발급 · 세션 \(sessionFolder)"
}

/// 사용자·MCP 호출자에게 보일 오류 문구. 우리 오류(`OTPError`·`StoreError`·`VaultError`)는 한국어 설명을 쓴다 —
/// `LocalizedError`가 아니라서 `localizedDescription`은 쓸모없는 문구가 된다. 그 밖(저장 실패의 `POSIXError` 등)은 시스템 설명을 쓴다.
func userMessage(for error: Error) -> String {
    switch error {
    case is OTPError, is StoreError, is VaultError: return String(describing: error)
    default: return error.localizedDescription
    }
}

/// 저장소에 든 Secure Enclave 키 조각. 없거나 Base64가 아니면 손상.
func enclaveKeyData(_ store: StoreFile) throws -> Data {
    guard let text = store.seKey, let data = Data(base64Encoded: text) else { throw StoreError.corrupt }
    return data
}

/// 승인을 받고 저장소의 봉인을 연다(모든 시드가 든 평문 JSON). 요청과 결과를 `subject` 라벨로 감사 로그에 남긴다.
/// 열린 데이터는 쓴 뒤 부른 쪽이 `wipe`한다. 봉인이 손상된 경우(`.corrupt`)는 승인 결과가 아니라서 결과 줄을 남기지 않는다.
func openStoreWithApproval(_ store: StoreFile, subject: String, reason: String, timeoutSeconds: Double = 60) throws -> Data {
    guard let sealed = store.sealed else { throw StoreError.corrupt }
    let keyData = try enclaveKeyData(store)
    auditLog("approval_requested", label: subject)
    do {
        let opened = try unsealWithApproval(sealed, keyData: keyData, reason: reason, timeoutSeconds: timeoutSeconds)
        auditLog("approval_granted", label: subject)
        return opened
    } catch let error as VaultError {
        switch error {
        case .denied: auditLog("approval_denied", label: subject)
        case .timeout: auditLog("approval_timeout", label: subject)
        case .corrupt: break
        }
        throw error
    }
}

/// 시드 사전의 배열을 모두 0으로 덮는다. `keys`를 배열로 복사해 도는 것은, 뷰가 사전 저장소를 붙들고 있으면 값을 바꿀 때
/// 사전이 통째로 복사되어 원래 배열이 지워지지 않고 남기 때문이다. 다른 곳과 공유하는 배열은 쓰기 시 복사되어 이쪽 사본만 지워진다.
func wipe(_ secrets: inout SecretMap) {
    for label in Array(secrets.keys) { wipe(&secrets[label]!) }
}

/// 라벨의 코드를 발급한다: 저장소 읽기 → 승인(Touch ID) → 봉인 해제 → 그 계정 시드만 남기고 지우기 → 코드 계산(남은 시간이 짧으면 다음 주기까지 대기) → 시드 지우기 → 기록.
/// 승인 대기는 `timeoutSeconds`. 거절·시간 초과·없는 라벨은 오류로 올린다.
func issueForLabel(_ query: String, sessionFolder: String, timeoutSeconds: Double = 60) throws -> IssuedCode {
    let store = try loadStore()
    let entry = try resolveLabel(query, in: store.entries)
    let issued: IssuedCode
    do {  // 시드가 메모리에 있는 구간. 빠져나갈 때(오류 포함) defer가 지운다.
        var opened = try openStoreWithApproval(store, subject: entry.label,
                                               reason: approvalReason(label: entry.label, sessionFolder: sessionFolder),
                                               timeoutSeconds: timeoutSeconds)
        defer { wipe(&opened) }
        var secrets = try decodeSecrets(opened)
        defer { wipe(&secrets) }
        // 사전에서 꺼내 따로 쥐면 그 배열도 직접 지워야 한다(꺼내면 이 변수만 쥐고 있어 제자리에서 지워진다).
        guard var seed = secrets.removeValue(forKey: entry.label) else { throw StoreError.corrupt }
        defer { wipe(&seed) }
        // issueCode는 남은 시간이 짧으면 다음 주기까지 잠든다. 그동안 다른 계정의 시드(secrets)와 평문 묶음(opened)이 메모리에 남지 않게 지금 지운다.
        wipe(&secrets)
        wipe(&opened)
        issued = issueCode(secret: seed, algorithm: entry.algorithm, digits: entry.digits, period: entry.period,
                           now: Date().timeIntervalSince1970, sleep: Thread.sleep(forTimeInterval:))
    }
    auditLog("issued", label: entry.label)
    return issued
}
