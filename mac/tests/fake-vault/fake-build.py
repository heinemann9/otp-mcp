#!/usr/bin/env python3
"""가짜 Vault 빌드: Secure Enclave 대신 소프트웨어 키로 봉인을 여는 가짜 Vault를 끼운 CLI를 만든다.

Touch ID 없이 import·code·remove 흐름(승인 문구·감사 로그·저장 결과·오류 처리)을 끝까지 돌려 보려는 것이다.
원본은 건드리지 않고 소스를 복사해 Vault.swift의 세 함수(createEnclaveKey·enclavePublicKey·unsealWithApproval)만 바꾼다.
바꾸는 범위는 Vault.swift의 두 주석 «/// SE 안에 새 키를 만들고»부터 «/// 가져온 비밀값을 쓴 뒤 메모리를 0으로 덮는다» 앞까지다.
그 주석이 사라지면 main()의 text.index가 ValueError로 눈에 띄게 실패한다 — Vault.swift를 고칠 때 이 두 주석을 지키거나 여기를 함께 고친다.

가짜 승인 제어(환경 변수)
  FAKE_APPROVAL   grant(기본) | deny | timeout | corrupt
  FAKE_REASON_LOG 승인 문구를 이어 쓸 파일 경로

실행(어느 폴더에서든): python3 -I mac/tests/fake-vault/fake-build.py   →  mac/.build/fake-vault/otp-mcp-fake
이어서 흐름 시험: bash mac/tests/fake-vault/scenarios.sh   (Touch ID 불필요, 마지막 줄 «합계: 통과 N, 실패 0»)
"""
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]  # 이 파일 = <레포>/mac/tests/fake-vault/fake-build.py
SRC = REPO / "mac/Sources/otp-mcp"
OUT = REPO / "mac/.build/fake-vault"  # .build/는 git 무시 대상

FAKE = '''/// [시험용 가짜] SE 대신 소프트웨어 P-256 키. keyData = 개인키 raw 32바이트.
func createEnclaveKey() throws -> Data { P256.KeyAgreement.PrivateKey().rawRepresentation }

func enclavePublicKey(_ keyData: Data) throws -> P256.KeyAgreement.PublicKey {
    try P256.KeyAgreement.PrivateKey(rawRepresentation: keyData).publicKey
}

func unsealWithApproval(_ sealed: SealedSecrets, keyData: Data, reason: String, timeoutSeconds: Double = 60) throws -> Data {
    if let p = getenv("FAKE_REASON_LOG") {
        let line = Array((reason + "\\n").utf8)
        let fd = open(p, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        _ = write(fd, line, line.count)
        close(fd)
    }
    switch getenv("FAKE_APPROVAL").map({ String(cString: $0) }) ?? "grant" {
    case "deny": throw VaultError.denied("fake")
    case "timeout": throw VaultError.timeout
    case "corrupt": throw VaultError.corrupt
    default: break
    }
    let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: keyData)
    return try openSecrets(sealed) { try key.sharedSecretFromKeyAgreement(with: $0) }
}

'''


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "src").mkdir(parents=True)
    for f in SRC.glob("*.swift"):
        shutil.copy(f, OUT / "src" / f.name)
    vault = OUT / "src/Vault.swift"
    text = vault.read_text(encoding="utf-8")
    start = text.index("/// SE 안에 새 키를 만들고")
    end = text.index("/// 가져온 비밀값을 쓴 뒤 메모리를 0으로 덮는다")
    vault.write_text(text[:start] + FAKE + text[end:], encoding="utf-8")
    cmd = ["swiftc", "-swift-version", "5", "-module-name", "otp_mcp_fake", "-o", str(OUT / "otp-mcp-fake")] + sorted(str(p) for p in (OUT / "src").glob("*.swift"))
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout + r.stderr)
    print("build exit =", r.returncode)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
