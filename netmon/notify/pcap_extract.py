"""알림 전후 ±N초 PCAP 조각 추출 (FR-3 2단계: tcpdump 링버퍼 → 조각).

링버퍼가 단기 보관한 pcap 들에서 알림 시각 주변 창과 (선택) 흐름 5-튜플에 맞는 패킷만
골라 조각 파일로 쓴다. 전체 페이로드는 영구 저장하지 않는다(정의서 §4): 링버퍼는 용량
상한으로 순환하고, 보존되는 것은 알림이 유발한 짧은 조각뿐이다.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
from scapy.utils import PcapReader, wrpcap

__all__ = ["FiveTuple", "extract_window"]


@dataclass(frozen=True, slots=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: str


def _matches(pkt: Packet, ft: FiveTuple) -> bool:
    if not pkt.haslayer(IP):
        return False
    ip = pkt[IP]
    src, dst = str(ip.src), str(ip.dst)
    proto = ""
    sport = dport = None
    if pkt.haslayer(TCP):
        proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
    forward = src == ft.src_ip and dst == ft.dst_ip
    reverse = src == ft.dst_ip and dst == ft.src_ip
    if not (forward or reverse):
        return False
    if ft.proto and proto and ft.proto.upper() != proto:
        return False
    ports_known = ft.src_port is not None and ft.dst_port is not None and sport is not None
    return not (ports_known and {ft.src_port, ft.dst_port} != {sport, dport})


def extract_window(
    pcap_paths: Iterable[Path | str],
    center: datetime,
    window_s: float,
    out_path: Path | str,
    flow: FiveTuple | None = None,
) -> int:
    """center ±window_s 초와 (선택) flow 에 맞는 패킷을 out_path 로 쓰고 개수를 반환한다."""
    center_epoch = center.timestamp()
    lo, hi = center_epoch - window_s, center_epoch + window_s
    kept: list[Packet] = []
    for path in pcap_paths:
        if not Path(path).exists():
            continue
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                t = float(pkt.time)
                if t < lo or t > hi:
                    continue
                if flow is not None and not _matches(pkt, flow):
                    continue
                kept.append(pkt)
    if kept:
        wrpcap(str(out_path), kept)
    return len(kept)
