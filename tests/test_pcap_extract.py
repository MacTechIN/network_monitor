"""PCAP 조각 추출: 시간 창과 흐름 5-튜플 필터가 맞는 패킷만 고르는지 검증한다."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

from netmon.notify.pcap_extract import FiveTuple, extract_window


def _pkt(t: float, src: str, dst: str, sport: int, dport: int) -> Packet:
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = t
    return pkt


def _ring(tmp_path: Path) -> Path:
    pkts = [
        _pkt(1000.0, "192.168.45.10", "203.0.113.5", 51000, 443),
        _pkt(1001.0, "192.168.45.10", "203.0.113.5", 51000, 443),
        _pkt(1002.0, "192.168.45.11", "198.51.100.7", 52000, 80),
        _pkt(1010.0, "192.168.45.10", "203.0.113.5", 51000, 443),
    ]
    path = tmp_path / "ring.pcap"
    wrpcap(str(path), pkts)
    return path


def test_window_only(tmp_path: Path) -> None:
    ring = _ring(tmp_path)
    center = datetime.fromtimestamp(1001.0, tz=UTC)
    out = tmp_path / "snippet.pcap"
    n = extract_window([ring], center, window_s=1.5, out_path=out)
    assert n == 3  # 1000, 1001, 1002 (1010 은 창 밖)
    assert out.exists()


def test_window_and_flow_filter(tmp_path: Path) -> None:
    ring = _ring(tmp_path)
    center = datetime.fromtimestamp(1001.0, tz=UTC)
    out = tmp_path / "snippet.pcap"
    flow = FiveTuple("192.168.45.10", "203.0.113.5", 51000, 443, "TCP")
    n = extract_window([ring], center, window_s=5.0, out_path=out, flow=flow)
    # 창 [996,1006] 안에서 해당 흐름: 1000, 1001 (1002 는 다른 흐름, 1010 은 창 밖)
    assert n == 2


def test_no_match_writes_nothing(tmp_path: Path) -> None:
    ring = _ring(tmp_path)
    center = datetime.fromtimestamp(5000.0, tz=UTC)
    out = tmp_path / "snippet.pcap"
    assert extract_window([ring], center, window_s=1.0, out_path=out) == 0
    assert not out.exists()
