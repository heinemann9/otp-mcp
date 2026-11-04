#!/bin/bash
# 가짜 Vault 흐름 시험: 가짜 Vault(fake-build.py)로 import·list·code·remove를 Touch ID 없이 끝까지 돌린다.
# 승인(Touch ID)은 가짜 Vault가 환경 변수로 흉내 낸다(FAKE_APPROVAL=deny|timeout|corrupt). 진짜 SE 경로는 `otp-mcp vault-check`가 본다.
# 실행(어느 폴더에서든): python3 -I mac/tests/fake-vault/fake-build.py && bash mac/tests/fake-vault/scenarios.sh
# Touch ID도 실제 저장소도 필요 없다. 코드 발급 시험이 30초 주기의 «안전한 구간»을 기다려 몇 분 걸린다.
# 마지막 줄이 «합계: 통과 N, 실패 0»이고 종료 코드가 0이면 합격이다. 실패한 항목은 FAIL과 rc·out·err를 보인다.
# 작업 폴더는 git 제외 폴더 .test-home/fake-vault* 이고, 모든 출력은 시드 누출 검사를 위해 모음 파일에 덧붙인다.
set -u
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)  # 이 파일 = <레포>/mac/tests/fake-vault/scenarios.sh
BIN=${BIN:-$REPO/mac/.build/fake-vault/otp-mcp-fake}
[ -x "$BIN" ] || { echo "가짜 빌드가 없다 — 먼저: python3 -I mac/tests/fake-vault/fake-build.py" >&2; exit 2; }
H=$REPO/.test-home/fake-vault
COLLECT=$REPO/.test-home/fake-vault-collect.txt
TMP_ERR=$REPO/.test-home/fake-vault-stderr.txt
VEC=$REPO/shared/testvectors.json
export OTP_MCP_HOME=$H
export FAKE_REASON_LOG=$H/reasons.txt
pass=0; fail=0
mkdir -p "$REPO/.test-home"  # git 무시 폴더라 새로 받은 레포에는 없다
: > "$COLLECT"

# 실제 저장소가 시험 전후로 달라지지 않았는지 보려고 먼저 상태를 적어 둔다.
REAL_APP="$HOME/Library/Application Support/otp-mcp"; REAL_LOG="$HOME/Library/Logs/otp-mcp.log"
real_before="$(ls -d "$REAL_APP" "$REAL_LOG" 2>&1 | tr '\n' ' ')"

reset() { rm -rf "$H"; mkdir -p "$H"; : > "$FAKE_REASON_LOG"; unset FAKE_APPROVAL; }
run() { # run <표준 입력> <인자...> → OUT ERR RC
  local input="$1"; shift
  OUT=$(printf -- "$input" | "$BIN" "$@" 2>"$TMP_ERR"); RC=$?
  ERR=$(cat "$TMP_ERR")
  { echo "--- $*"; echo "$OUT"; echo "$ERR"; } >> "$COLLECT"
}
t() { # t <이름> <조건 명령...>
  local name="$1"; shift
  if "$@"; then pass=$((pass+1)); echo "ok   $name"; else fail=$((fail+1)); echo "FAIL $name"; echo "     rc=$RC"; echo "     out=$OUT"; echo "     err=$ERR"; fi
}
has() { printf '%s' "$1" | grep -qF -- "$2"; }
lacks() { ! has "$1" "$2"; }
eq() { [ "$1" = "$2" ]; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
lines() { printf '%s\n' "$1" | grep -c . ; }
logcount() { local n; n=$(grep -c -F -- "$1" "$H/otp-mcp.log" 2>/dev/null); echo "${n:-0}"; }
safe_window() { # 코드 경계(남은 10초 미만이면 CLI가 다음 주기까지 기다린다)와 별도 계산 사이의 어긋남을 피한다
  # 30초 주기에서 초(s)가 20을 넘으면 기다리므로, 이어지는 몇 초짜리 실행이 끝날 때까지 20 아래에 머무는 3~14초 구간에서 시작한다.
  while :; do s=$(( $(date +%s) % 30 )); if [ "$s" -ge 3 ] && [ "$s" -le 14 ]; then break; fi; sleep 1; done
}
expect_code() { # <base32 시드> <알고리즘> <자릿수> <주기> → 지금 시각의 코드
  python3 -I - "$@" <<'PY'
import base64, hashlib, hmac, struct, sys, time
sec, algo, digits, period = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
key = base64.b32decode(sec.upper() + "=" * ((8 - len(sec) % 8) % 8))
h = hmac.new(key, struct.pack(">Q", int(time.time()) // period), getattr(hashlib, algo.lower())).digest()
o = h[-1] & 15
print(str((int.from_bytes(h[o:o + 4], "big") & 0x7fffffff) % 10 ** digits).zfill(digits))
PY
}
vec() { python3 -I -c "import json,sys;d=json.load(open('$VEC'));print(eval(sys.argv[1]))" "$1"; }
jq_py() { python3 -I -c "import json,sys;d=json.load(open(sys.argv[1]));print(eval(sys.argv[2]))" "$1" "$2"; }

ALICE_SEED=$(vec 'd["migration"]["entries"][0]["secret"]')
BOB_SEED=$(vec 'd["migration"]["entries"][1]["secret"]')
MIG_URI=$(vec 'd["migration"]["uri"]')
ALICE='Example:alice@example.com'; BOB='Example2:bob'
FIX=$REPO/.test-home/fake-vault-fixtures; mkdir -p "$FIX"
QR=$FIX/test-qr.png
TXT=$FIX/uris.txt

fresh() { reset; [ -e "$QR" ] || "$BIN" test-qr "$MIG_URI" "$QR" >/dev/null; }

echo "=== A. 첫 가져오기(빈 저장소 — 승인 없음)"
fresh
run '\n\n\n' import "$QR"
t "A1 종료 코드 0" eq "$RC" 0
t "A2 HOTP 건너뜀 출력" has "$OUT" '건너뜀: Example3 carol (HOTP)'
t "A3 MD5 건너뜀 출력" has "$OUT" '건너뜀: Example4 dave (MD5)'
t "A4 번호 목록(알고리즘·자릿수·주기)" has "$OUT" '2. Example2:bob  (SHA256 7자리 30초)'
t "A5 선택 질문" has "$OUT" '가져올 번호(쉼표로 구분, 엔터=전부): '
t "A6 라벨 질문(기본값)" has "$OUT" '라벨 [Example:alice@example.com]: '
t "A7 가져왔습니다: 2개 + 지우기 안내" has "$OUT" "가져왔습니다: 2개. 이미지 파일을 지우세요: $QR"
t "A8 승인 요청 없음(빈 저장소)" eq "$(lines "$(cat "$FAKE_REASON_LOG")")" 0
run '' list
t "A9 list 두 줄" eq "$OUT" "$ALICE
$BOB"
t "A10 store.json 0600" eq "$(stat -f %Lp "$H/store.json")" 600
t "A11 store에 seKey·sealed" eq "$(jq_py "$H/store.json" '("seKey" in d, "sealed" in d, len(d["entries"]))')" "(True, True, 2)"
t "A12 감사 로그 import 2줄" eq "$(logcount $'\timport\t')" 2

echo "=== B. code"
safe_window
run '' code "$ALICE"
EXP=$(expect_code "$ALICE_SEED" sha1 6 30)
t "B1 종료 코드 0" eq "$RC" 0
t "B2 형식 '<6자리>  (남은 n초)'" bash -c '[[ "$1" =~ ^[0-9]{6}\ \ \(남은\ [0-9]+초\)$ ]]' _ "$OUT"
t "B3 코드가 별도 계산과 같다(alice)" eq "${OUT%%  *}" "$EXP"
t "B4 승인 문구" eq "$(tail -1 "$FAKE_REASON_LOG")" "$ALICE OTP 발급 · 세션 터미널"
t "B5 로그 순서 requested→granted→issued" eq "$(grep -F "$ALICE" "$H/otp-mcp.log" | cut -f2 | tail -3 | tr '\n' ' ')" "approval_requested approval_granted issued "
run '' code "$BOB"
t "B6 bob(SHA256·7자리) 코드 일치" eq "${OUT%%  *}" "$(expect_code "$BOB_SEED" sha256 7 30)"
run '' code 'EXAMPLE:ALICE@example.com'
t "B7 대소문자 무시 라벨" eq "${OUT%%  *}" "$(expect_code "$ALICE_SEED" sha1 6 30)"
t "B7c 승인 문구에도 해석된 라벨" eq "$(tail -1 "$FAKE_REASON_LOG")" "$ALICE OTP 발급 · 세션 터미널"
t "B7b 로그에는 해석된 라벨(입력 그대로가 아님)" eq "$(tail -1 "$H/otp-mcp.log" | cut -f2,3)" "issued	$ALICE"
n_req=$(logcount approval_requested); n_reason=$(lines "$(cat "$FAKE_REASON_LOG")")
run '' code nope
t "B8 없는 라벨: 종료 1, 목록 안내" bash -c '[ "$1" = 1 ] && [[ "$2" == *"라벨이 없습니다"* ]] && [[ "$2" == *"Example:alice@example.com, Example2:bob"* ]]' _ "$RC" "$ERR"
t "B9 없는 라벨은 승인도 로그도 없다" eq "$(logcount approval_requested)/$(lines "$(cat "$FAKE_REASON_LOG")")" "$n_req/$n_reason"
t "B10 표준 출력 비어 있음" eq "$OUT" ""

echo "=== C. 승인 거절·시간 초과·손상"
before=$(logcount $'\tissued\t')
FAKE_APPROVAL=deny run '' code "$ALICE"
t "C1 거절: 종료 1" eq "$RC" 1
t "C2 거절 문구" has "$ERR" '승인 또는 키 사용에 실패했습니다(fake)'
t "C3 거절: 표준 출력 비어 있음(코드 없음)" eq "$OUT" ""
t "C4 거절: 로그 requested→denied" eq "$(tail -2 "$H/otp-mcp.log" | cut -f2 | tr '\n' ' ')" "approval_requested approval_denied "
t "C5 거절: issued 늘지 않음" eq "$(logcount $'\tissued\t')" "$before"
FAKE_APPROVAL=timeout run '' code "$ALICE"
t "C6 시간 초과 문구" has "$ERR" '승인 대기 시간(60초)이 지났습니다'
t "C7 시간 초과 로그" eq "$(tail -2 "$H/otp-mcp.log" | cut -f2 | tr '\n' ' ')" "approval_requested approval_timeout "
FAKE_APPROVAL=corrupt run '' code "$ALICE"
t "C8 손상 문구" has "$ERR" '봉인된 데이터가 손상되었습니다'
t "C9 손상: 결과 줄 없이 requested만" eq "$(tail -1 "$H/otp-mcp.log" | cut -f2)" approval_requested

echo "=== D. 다시 가져오기(덮어쓰기 질문·기존 봉인 승인)"
sha0=$(sha "$H/store.json")
run '\n\n\ny\ny\n' import "$QR"
t "D1 종료 0·2개" bash -c '[ "$1" = 0 ] && [[ "$2" == *"가져왔습니다: 2개"* ]]' _ "$RC" "$OUT"
t "D2 덮어쓰기 질문 2번" eq "$(printf '%s\n' "$OUT" | grep -cF "을(를) 덮어쓸까요? (y/N): ")" 2
t "D3 질문 문구" has "$OUT" "'Example:alice@example.com'을(를) 덮어쓸까요? (y/N): "
t "D4 승인 문구(기존 봉인)" eq "$(tail -1 "$FAKE_REASON_LOG")" '가져오기 · 기존 항목 다시 봉인'
t "D5 새로 봉인됨(파일이 바뀜)" bash -c '[ "$1" != "$2" ]' _ "$sha0" "$(sha "$H/store.json")"
run '' list
t "D6 list 여전히 2줄" eq "$(lines "$OUT")" 2
safe_window
run '' code "$ALICE"; A_CODE=${OUT%%  *}
run '' code "$BOB"; B_CODE=${OUT%%  *}
t "D7 다시 봉인한 뒤에도 alice 시드 보존" eq "$A_CODE" "$(expect_code "$ALICE_SEED" sha1 6 30)"
t "D8 다시 봉인한 뒤에도 bob 시드 보존" eq "$B_CODE" "$(expect_code "$BOB_SEED" sha256 7 30)"
sha1=$(sha "$H/store.json")
run '\n\n\nn\nn\n' import "$QR"
t "D9 모두 거절: 가져온 항목 없음, 종료 0" bash -c '[ "$1" = 0 ] && [[ "$2" == *"가져온 항목이 없습니다"* ]]' _ "$RC" "$OUT"
t "D10 모두 거절: 저장 파일 그대로" eq "$(sha "$H/store.json")" "$sha1"
imports_before=$(logcount $'\timport\t')
run '\n\n\ny\nn\n' import "$QR"
t "D11 하나만 수락: 1개" has "$OUT" '가져왔습니다: 1개'
t "D12 감사 로그 import는 반영된 1건만" eq "$(( $(logcount $'\timport\t') - imports_before ))" 1
sha2=$(sha "$H/store.json")
FAKE_APPROVAL=deny run '\n\n\ny\ny\n' import "$QR"
t "D13 승인 거절: 종료 1·저장 그대로" bash -c '[ "$1" = 1 ] && [ "$2" = "$3" ]' _ "$RC" "$sha2" "$(sha "$H/store.json")"
t "D14 승인 거절이면 덮어쓰기 질문 없음" lacks "$OUT" '덮어쓸까요'

echo "=== E. remove"
sha3=$(sha "$H/store.json")
box_before=$(jq_py "$H/store.json" 'd["sealed"]["box"]')
FAKE_APPROVAL=deny run '' remove "$BOB"
t "E1 거절: 종료 1·저장 그대로" bash -c '[ "$1" = 1 ] && [ "$2" = "$3" ]' _ "$RC" "$sha3" "$(sha "$H/store.json")"
n_reason=$(lines "$(cat "$FAKE_REASON_LOG")")
run '' remove nope
t "E2 없는 라벨: 종료 1·승인 요청 없음" eq "$RC/$(lines "$(cat "$FAKE_REASON_LOG")")" "1/$n_reason"
run '' remove "$BOB"
t "E3 삭제 문구" eq "$OUT" "삭제했습니다: $BOB"
t "E4 승인 문구" eq "$(tail -1 "$FAKE_REASON_LOG")" "삭제 · $BOB"
t "E5b 삭제하면 봉인이 새로 만들어진다" bash -c '[ "$1" != "$2" ]' _ "$box_before" "$(jq_py "$H/store.json" 'd["sealed"]["box"]')"
t "E5 로그 remove" eq "$(tail -1 "$H/otp-mcp.log" | cut -f2,3)" "remove	$BOB"
run '' list
t "E6 list에 alice만" eq "$OUT" "$ALICE"
safe_window
run '' code "$ALICE"
t "E7 남은 alice 시드 보존(다시 봉인됨)" eq "${OUT%%  *}" "$(expect_code "$ALICE_SEED" sha1 6 30)"
run '' code "$BOB"
t "E8 지운 bob은 없는 라벨" has "$ERR" '라벨이 없습니다'
KEY_BEFORE=$(jq_py "$H/store.json" 'd["seKey"]')
run '' remove "$ALICE"
t "E9 마지막 항목 삭제" eq "$OUT" "삭제했습니다: $ALICE"
t "E10 마지막 삭제: entries 빔·sealed 없음·seKey 남음" eq "$(jq_py "$H/store.json" '(len(d["entries"]), "sealed" in d, d.get("seKey") is not None)')" "(0, False, True)"
run '' list
t "E11 빈 list: 표준 출력 비고 안내는 표준 오류, 종료 0" bash -c '[ "$1" = 0 ] && [ -z "$2" ] && [[ "$3" == *"등록된 계정이 없습니다"* ]]' _ "$RC" "$OUT" "$ERR"
n_reason=$(lines "$(cat "$FAKE_REASON_LOG")")
run '\n\n\n' import "$QR"
t "E12 비운 저장소에 다시 가져오기: 승인 없음" eq "$(lines "$(cat "$FAKE_REASON_LOG")")" "$n_reason"
t "E13 같은 SE 키를 다시 쓴다" eq "$(jq_py "$H/store.json" 'd["seKey"]')" "$KEY_BEFORE"
run '' list
t "E14 list 2줄" eq "$(lines "$OUT")" 2

echo "=== F. 깨진 저장 파일은 덮어쓰지 않는다"
fresh
printf '{깨짐' > "$H/store.json"; shaF=$(sha "$H/store.json")
run '\n\n\n' import "$QR"
t "F1 import: 종료 1·손상 문구" bash -c '[ "$1" = 1 ] && [[ "$2" == *"저장 파일을 읽을 수 없습니다"* ]]' _ "$RC" "$ERR"
t "F2 질문 전에 멈춘다" lacks "$OUT" '가져올 번호'
t "F3 저장 파일 그대로" eq "$(sha "$H/store.json")" "$shaF"
run '' list;   t "F4 list 손상 문구" has "$ERR" '저장 파일을 읽을 수 없습니다'
run '' code x; t "F5 code 손상 문구" has "$ERR" '저장 파일을 읽을 수 없습니다'
run '' remove x; t "F6 remove 손상 문구·그대로" bash -c '[[ "$1" == *"저장 파일을 읽을 수 없습니다"* ]] && [ "$2" = "$3" ]' _ "$ERR" "$shaF" "$(sha "$H/store.json")"
t "F7 승인 요청 없음" eq "$(lines "$(cat "$FAKE_REASON_LOG")")" 0
# 항목은 있는데 봉인이 없는 저장소(손상)도 덮어쓰지 않는다
fresh
printf '{"version":1,"entries":[{"label":"a","issuer":"","name":"","algorithm":"SHA1","digits":6,"period":30}]}' > "$H/store.json"; shaF2=$(sha "$H/store.json")
run '\n\n\n' import "$QR"
t "F8 봉인 없는 항목 저장소: 종료 1·그대로" bash -c '[ "$1" = 1 ] && [ "$2" = "$3" ]' _ "$RC" "$shaF2" "$(sha "$H/store.json")"

echo "=== G. 선택·라벨 입력"
fresh; run '2\n\n' import "$QR"
t "G1 2번만" bash -c '[[ "$1" == *"가져왔습니다: 1개"* ]]' _ "$OUT"
run '' list; t "G2 list = bob" eq "$OUT" "$BOB"
fresh; run '1,1\n\n' import "$QR"
t "G3 같은 번호 중복 제거(라벨 질문 1번)" eq "$(printf '%s\n' "$OUT" | grep -cF '라벨 [')" 1
for bad in 3 0 x '1,,2' '-1'; do
  fresh; run "$bad"'\n' import "$QR"
  t "G4 잘못된 번호 '$bad': 종료 1·저장 없음" bash -c '[ "$1" = 1 ] && [[ "$2" == *"번호를 읽을 수 없습니다"* ]] && [ ! -e "$3" ]' _ "$RC" "$ERR" "$H/store.json"
done
fresh; run '' import "$QR"
t "G5 선택 단계에서 입력 끝: 취소·저장 없음" bash -c '[ "$1" = 1 ] && [[ "$2" == *"입력이 끝나 가져오기를 취소했습니다"* ]] && [ ! -e "$3" ]' _ "$RC" "$ERR" "$H/store.json"
fresh; run '\n' import "$QR"
t "G6 라벨 단계에서 입력 끝: 취소·저장 없음" bash -c '[ "$1" = 1 ] && [[ "$2" == *"입력이 끝나"* ]] && [ ! -e "$3" ]' _ "$RC" "$ERR" "$H/store.json"
fresh; run '\n  github  \naws\n' import "$QR"
run '' list
t "G7 직접 입력한 라벨(앞뒤 공백 제거)" eq "$OUT" "github
aws"
safe_window
run '' code GitHub
t "G8 입력한 라벨로 발급(대소문자 무시)" eq "${OUT%%  *}" "$(expect_code "$ALICE_SEED" sha1 6 30)"
fresh; run '1\n\033[2Jevil\n' import "$QR"
run '' list
t "G9 라벨의 제어 문자는 공백" eq "$(printf '%s' "$OUT" | python3 -I -c 'import sys;print("\x1b" in sys.stdin.read())')" False
fresh; run '1\nx\n\n' import "$QR"  # 한 개만 고르고 라벨 x
run '1\nx\ny\n' import "$QR"
t "G10 같은 라벨 다시 가져오면 덮어쓰기 질문" has "$OUT" "'x'을(를) 덮어쓸까요? (y/N): "

fresh; run '\nx\nx\ny\n' import "$QR"
t "G11 같은 묶음에서 같은 라벨 두 번: 덮어쓰기 질문" has "$OUT" "'x'을(를) 덮어쓸까요? (y/N): "
run '' list
t "G12 한 줄만 남는다" eq "$OUT" x
safe_window
run '' code x
t "G13 뒤에 온 항목(bob)의 시드가 남는다" eq "${OUT%%  *}" "$(expect_code "$BOB_SEED" sha256 7 30)"

echo "=== J. 중복 규칙 3(issuer·name·시드 같음 — unique_id 없는 주소)"
fresh
printf 'otpauth://totp/GitHub:me@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub\n' > "$FIX/github.txt"
run '\na\n' import "$FIX/github.txt"
run '\nb\nn\n' import "$FIX/github.txt"
t "J1 다른 라벨이어도 같은 계정이면 기존 라벨('a')을 덮어쓸지 묻는다" has "$OUT" "'a'을(를) 덮어쓸까요? (y/N): "
run '' list
t "J2 거절하면 그대로(a만)" eq "$OUT" a
run '\nb\ny\n' import "$FIX/github.txt"
run '' list
t "J3 수락하면 b로 바뀌고 a는 사라진다" eq "$OUT" b

echo "=== H. 글자 파일·여러 파일"
fresh
cat > "$TXT" <<'EOF'
# 주석
otpauth://totp/GitHub:me@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub
   OTPAUTH://totp/AWS:me?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60
https://example.com/not-otp
EOF
run '\n\n\n' import "$TXT"
t "H1 글자 파일 2개 가져옴(주석·다른 줄 무시)" bash -c '[ "$1" = 0 ] && [[ "$2" == *"가져왔습니다: 2개"* ]]' _ "$RC" "$OUT"
safe_window
run '' code 'GitHub:me@example.com'
t "H2 GitHub(SHA1·6) 코드" eq "${OUT%%  *}" "$(expect_code GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ sha1 6 30)"
run '' code 'AWS:me'
t "H3 AWS(SHA256·8·60초) 코드" eq "${OUT%%  *}" "$(expect_code GEZDGNBVGY3TQOJQ sha256 8 60)"
fresh; run '\n\n\n\n\n\n' import "$QR" "$TXT"
t "H4 이미지+글자 파일 함께: 4개·안내에 두 경로" bash -c '[[ "$1" == *"가져왔습니다: 4개"* ]] && [[ "$1" == *"$2, $3"* ]]' _ "$OUT" "$QR" "$TXT"
fresh; printf 'otpauth://hotp/X:y?secret=GEZDGNBVGY3TQOJQ&counter=1\n' > "$FIX/hotp.txt"
run '\n' import "$FIX/hotp.txt"
t "H5 HOTP 주소: 종료 1·사유·저장 없음" bash -c '[ "$1" = 1 ] && [[ "$2" == *"HOTP"* ]] && [ ! -e "$3" ]' _ "$RC" "$ERR" "$H/store.json"
printf 'hello\n' > "$FIX/hello.txt"
run '' import "$FIX/hello.txt"
t "H6 OTP 줄 없음: 종료 1" bash -c '[ "$1" = 1 ] && [[ "$2" == *"주소를 찾지 못함"* ]]' _ "$RC" "$ERR"
run '' import "$H/없는파일.png"
t "H7 없는 파일: 한국어 문구·경로" bash -c '[ "$1" = 1 ] && [[ "$2" == *"파일을 읽을 수 없음"* ]] && [[ "$2" == *"없는파일.png"* ]]' _ "$RC" "$ERR"
printf 'not an image' > "$H/garbage.png"
run '' import "$H/garbage.png"
t "H8 이미지가 아닌 .png: 한국어 문구" bash -c '[ "$1" = 1 ] && [[ "$2" == *"이미지나 UTF-8 글자 파일이 아님"* ]]' _ "$RC" "$ERR"

echo "=== I. 누출·권한·실제 저장소"
fresh; run '\n\n\n\n\n\n' import "$QR" "$TXT"
for needle in "$ALICE_SEED" "${BOB_SEED%%=*}" GEZDGNBVGY3TQOJQ otp-mcp-fake-seed; do
  t "I1 모음 파일에 시드 조각 없음: ${needle:0:10}…" bash -c '! grep -qF -- "$1" "$2"' _ "$needle" "$COLLECT"
done
python3 -I - "$COLLECT" "$H/store.json" "$H/otp-mcp.log" "$VEC" > "$H/leak.txt" <<'PY'
import base64, json, sys
v = json.load(open(sys.argv[4]))
needles = []
for e in v["migration"]["entries"]:
    raw = base64.b32decode(e["secret"])
    b64 = base64.b64encode(raw).decode()
    needles += [raw.decode("latin1"), b64, b64.rstrip("="), raw.hex()]
raw = base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
needles += [raw.decode("latin1"), base64.b64encode(raw).decode()]
for fn in sys.argv[1:4]:
    data = open(fn, "rb").read().decode("latin1")
    for n in needles:
        if n in data:
            print("LEAK", fn, n[:8])
PY
t "I2 모음·store.json·로그에 시드(원본·Base64·hex) 없음" eq "$(cat "$H/leak.txt")" ""
t "I3 store.json 0600" eq "$(stat -f %Lp "$H/store.json")" 600
t "I4 로그 0600" eq "$(stat -f %Lp "$H/otp-mcp.log")" 600
real_after="$(ls -d "$REAL_APP" "$REAL_LOG" 2>&1 | tr '\n' ' ')"
t "I5 실제 저장소·로그가 시험 전후로 같다" eq "$real_after" "$real_before"

echo
echo "합계: 통과 $pass, 실패 $fail"
[ "$fail" = 0 ]
