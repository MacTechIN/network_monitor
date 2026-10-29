"""Safety guard: flag shell commands that cross the project's hard constraints.

network_monitor is a detect-only IDS on an owned/administered network
(see ``doc/01_project_definition.md`` §4, §8). It must never:

* perform offensive or active-MITM techniques — ARP/WiFi spoofing, deauth,
  evil-twin, TLS interception;
* block traffic — no firewall drop/reject rules (it is an IDS, not an IPS);
* run active scans ad hoc — scanning happens only through the app's opt-in
  config path, never from a loose shell command.

This module recognises command lines that break those rules so a Claude Code
``PreToolUse`` hook on the developer PC (see ``.claude/hooks/``) can reject them
before they run, and so runtime code can refuse them too. It is deliberately
conservative: it blocks only well-known offensive tools and unambiguous
drop/reject firewall edits, and allows everything else (including the tools the
project does use, such as ``suricata -r`` and ``tcpreplay``).
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass

__all__ = ["Verdict", "classify", "main"]


@dataclass(frozen=True, slots=True)
class Verdict:
    """A blocked command and why."""

    category: str
    reason: str


# (category, human reason, compiled pattern). First match wins.
_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "spoofing",
        "ARP/WiFi 스푸핑·중간자 도구는 공격 기법이라 IDS 센서로 쓸 수 없다 "
        "(정의서 §4, 방식 D 미채택)",
        re.compile(
            r"\b(arpspoof|arp-spoof|ettercap|bettercap|dsniff|macof|"
            r"aireplay-ng|airbase-ng|mdk3|mdk4|wifiphisher|yersinia|nemesis)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "mitm_tls",
        "TLS 복호화/중간자 도구는 금지된다. 암호화 트래픽은 메타데이터만 본다 (정의서 §8)",
        re.compile(r"\b(sslstrip|sslsplit|mitmproxy|mitmdump)\b", re.IGNORECASE),
    ),
    (
        "block",
        "트래픽 차단 규칙(drop/reject)은 금지된다. 이 프로젝트는 IDS이지 IPS가 아니다 (정의서 §4)",
        re.compile(
            r"\b(?:ip6?tables|ebtables)\b.*\B-j\s+(?:DROP|REJECT)\b"
            r"|\bnft\b.*\b(?:drop|reject)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "active_scan",
        "능동 스캔은 ad-hoc 셸이 아니라 설정의 opt-in 경로로만 수행한다 (정의서 §6.2, 기본 OFF)",
        re.compile(r"\b(nmap|masscan|zmap|unicornscan|arp-scan)\b", re.IGNORECASE),
    ),
)


def classify(command: str) -> Verdict | None:
    """Return a :class:`Verdict` if ``command`` violates a hard constraint, else ``None``."""
    for category, reason, pattern in _RULES:
        if pattern.search(command):
            return Verdict(category=category, reason=reason)
    return None


def main() -> int:
    """PreToolUse hook entry point.

    Reads a Claude Code hook payload (JSON) on stdin. For a ``Bash`` tool call it
    classifies the command; a violation is printed to stderr and the process exits
    with code 2 (which tells Claude Code to block the call). Anything else, and any
    unparsable/other input, exits 0 so the guard never breaks ordinary tooling.
    """
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return 0
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0
    verdict = classify(command)
    if verdict is None:
        return 0
    sys.stderr.write(f"[netmon guard: {verdict.category}] 차단됨 — {verdict.reason}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
