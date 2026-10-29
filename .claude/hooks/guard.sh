#!/usr/bin/env bash
# PreToolUse 훅 shim: 하드 제약 위반 명령을 차단한다. 로직은 netmon/guard.py 에 있다.
# 활성화 방법은 .claude/hooks/README.md 참고. (이 파일만으로는 동작하지 않는다.)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
py="$root/.venv/bin/python"
[ -x "$py" ] || py="$(command -v python3)"
cd "$root"
exec "$py" -m netmon.guard
