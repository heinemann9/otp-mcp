#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
swift build -c release
codesign -f -s - -o runtime .build/release/otp-mcp
mkdir -p ~/.local/bin
install -m 755 .build/release/otp-mcp ~/.local/bin/otp-mcp
codesign -dv ~/.local/bin/otp-mcp 2>&1 | grep runtime >/dev/null && echo "설치: ~/.local/bin/otp-mcp (하드닝 런타임)"  # grep -q는 첫 일치에서 끝나 codesign이 SIGPIPE(141)로 죽는다
