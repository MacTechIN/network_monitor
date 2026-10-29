"""netmon.guard 가 하드 제약 위반 명령만 정확히 차단하는지 검증한다."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from netmon.guard import classify

REPO_ROOT = Path(__file__).resolve().parent.parent

BLOCKED: list[tuple[str, str]] = [
    ("arpspoof -i eth0 -t 192.168.45.10 192.168.45.1", "spoofing"),
    ("sudo ettercap -T -M arp:remote //192.168.45.1// //", "spoofing"),
    ("bettercap -iface wlan0", "spoofing"),
    ("aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon", "spoofing"),
    ("mdk4 wlan0mon d", "spoofing"),
    ("mitmproxy --mode transparent", "mitm_tls"),
    ("sslstrip -l 8080", "mitm_tls"),
    ("iptables -A FORWARD -s 192.168.45.10 -j DROP", "block"),
    ("sudo nft add rule inet filter forward ip saddr 192.168.45.10 drop", "block"),
    ("nmap -sS 192.168.45.0/24", "active_scan"),
    ("masscan 192.168.45.0/24 -p0-65535", "active_scan"),
    ("arp-scan --localnet", "active_scan"),
]

ALLOWED: list[str] = [
    "git status",
    "suricata -r tests/pcaps/sample.pcap -l /tmp/out",
    "tcpreplay --mbps 100 -i eth0 tests/pcaps/sample.pcap",
    "ruff check .",
    "pytest -q",
    "nft list ruleset",  # 조회는 drop/reject 가 없으므로 허용
    "sudo apt-get install -y suricata",
    "python -m netmon.guard",
]


@pytest.mark.parametrize(("command", "category"), BLOCKED)
def test_blocked_commands(command: str, category: str) -> None:
    verdict = classify(command)
    assert verdict is not None, f"차단되어야 하는데 통과함: {command}"
    assert verdict.category == category


@pytest.mark.parametrize("command", ALLOWED)
def test_allowed_commands(command: str) -> None:
    assert classify(command) is None, f"허용되어야 하는데 차단됨: {command}"


def _run_hook(payload: dict[str, object]) -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "netmon.guard"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    return proc.returncode


def test_hook_blocks_bash_spoofing() -> None:
    assert _run_hook({"tool_name": "Bash", "tool_input": {"command": "arpspoof -i eth0"}}) == 2


def test_hook_allows_safe_bash() -> None:
    assert _run_hook({"tool_name": "Bash", "tool_input": {"command": "git status"}}) == 0


def test_hook_ignores_non_bash_and_garbage() -> None:
    assert _run_hook({"tool_name": "Read", "tool_input": {"file_path": "x"}}) == 0
    proc = subprocess.run(
        [sys.executable, "-m", "netmon.guard"],
        input="not json",
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert proc.returncode == 0
