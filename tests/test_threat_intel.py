"""P4.2 위협 인텔: 키 없는 로컬 피드(Feodo/SSLBL/Spamhaus)로 매칭 + warninglist 오탐 억제."""

from __future__ import annotations

from pathlib import Path

from netmon.enrich.threat_intel import ThreatIntel

FIX = Path(__file__).resolve().parent / "fixtures" / "threat"


def _loaded(with_warninglist: bool = True) -> ThreatIntel:
    ti = ThreatIntel()
    ti.add_ip_blocklist(FIX / "feodo_ipblocklist.txt", "feodo", "botnet_c2")
    ti.add_ip_blocklist(FIX / "sslbl_ipblocklist.csv", "sslbl", "botnet_c2")
    ti.add_cidr_blocklist(FIX / "spamhaus_drop.txt", "spamhaus_drop", "drop")
    if with_warninglist:
        ti.add_warninglist_json(FIX / "warninglist.json")
    return ti


def test_ip_blocklist_match() -> None:
    ti = _loaded(with_warninglist=False)
    m = ti.match("185.220.101.5")
    assert m is not None and m.source == "feodo" and m.category == "botnet_c2"

    s = ti.match("91.219.236.100")  # SSLBL CSV 에서
    assert s is not None and s.source == "sslbl"


def test_cidr_blocklist_match_with_reference() -> None:
    ti = _loaded(with_warninglist=False)
    m = ti.match("91.200.1.1")
    assert m is not None and m.source == "spamhaus_drop" and m.reference == "SBL000002"


def test_warninglist_suppresses_false_positive() -> None:
    ti = _loaded(with_warninglist=True)
    # 45.142.212.10 은 Feodo 에 있지만 warninglist(45.142.212.0/24)로 억제된다.
    assert ti.is_allowlisted("45.142.212.10") is True
    assert ti.match("45.142.212.10") is None
    # 억제 전이라면 매칭됐어야 함을 대조.
    assert _loaded(with_warninglist=False).match("45.142.212.10") is not None


def test_non_global_and_clean_ip_return_none() -> None:
    ti = _loaded()
    assert ti.match("203.0.113.5") is None  # DROP 에 있어도 비글로벌 → None
    assert ti.match("10.0.0.1") is None  # 사설
    assert ti.match("1.1.1.1") is None  # 어느 피드에도 없음
    assert ti.match("garbage") is None
