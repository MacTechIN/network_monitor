# 개발 PC 안전 훅 (PreToolUse)

이 훅은 하드 제약(스푸핑·차단·무단 능동 스캔 금지)을 어기는 셸 명령을 Claude Code가
실행하기 전에 막는다. 로직은 `netmon/guard.py`에, 진입점은 `guard.sh`에 있다.

## 활성화

`.claude/settings.json`에 아래를 추가한다(없으면 새로 만든다). 세션 중 자동 반영되지
않을 수 있으므로 Claude Code를 재시작한다.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": ".claude/hooks/guard.sh" } ] }
    ]
  }
}
```

병행 권장: `.claude/settings.json`의 `permissions.deny`에 `Bash(arpspoof:*)`,
`Bash(ettercap:*)`, `Bash(nmap:*)` 등을 함께 넣는다(심층 방어).

## 동작

stdin으로 받은 훅 페이로드가 `Bash`이고 명령이 위반이면 종료 코드 2 + 사유를 stderr로
낸다(그 외에는 0). 판정 규칙과 테스트는 `netmon/guard.py`, `tests/test_guard.py` 참고.
