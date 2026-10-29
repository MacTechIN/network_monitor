"""수동(passive) 자산 발견: ARP/DHCP/mDNS 패킷에서 기기 관측을 추출한다.

능동 스캔(arp-scan/nmap)을 하지 않는다(정의서 §4, 기본 OFF). 관측은 복합 신원 계산
(:mod:`netmon.discovery.identity`)으로 넘어간다. 라이브 sniff 루프는 systemd 가 수명을
관리하며 단위 테스트하지 않는다(파서 함수만 테스트).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from netmon.discovery.identity import DeviceObservation, normalize_mac

__all__ = ["observe", "observe_arp", "observe_dhcp", "observe_mdns", "sniff_forever"]


def _as_text(value: Any) -> str | None:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace") or None
    if isinstance(value, str):
        return value or None
    return None


def _as_hex(value: Any) -> str | None:
    if isinstance(value, bytes | bytearray):
        return bytes(value).hex() or None
    if isinstance(value, str):
        return value or None
    return None


def observe_arp(pkt: Packet) -> DeviceObservation | None:
    if not pkt.haslayer(ARP):
        return None
    arp = pkt[ARP]
    mac = str(arp.hwsrc)
    if not mac or mac == "00:00:00:00:00:00":
        return None
    return DeviceObservation(mac=normalize_mac(mac), ip=str(arp.psrc) or None)


def observe_dhcp(pkt: Packet) -> DeviceObservation | None:
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return None
    mac = normalize_mac(":".join(f"{b:02x}" for b in bytes(pkt[BOOTP].chaddr)[:6]))
    hostname = fingerprint = client_id = None
    for opt in pkt[DHCP].options:
        if not isinstance(opt, tuple) or not opt:
            continue
        name = opt[0]
        if name == "hostname":
            hostname = _as_text(opt[1]) if len(opt) > 1 else None
        elif name == "param_req_list":
            raw = opt[1] if len(opt) == 2 else opt[1:]
            vals = list(raw) if isinstance(raw, bytes | bytearray | list | tuple) else [raw]
            fingerprint = ",".join(str(int(v)) for v in vals) or None
        elif name == "client_id":
            client_id = _as_hex(opt[1]) if len(opt) > 1 else None
    ip = str(pkt[IP].src) if pkt.haslayer(IP) else None
    return DeviceObservation(
        mac=mac,
        ip=ip if ip and ip != "0.0.0.0" else None,
        dhcp_hostname=hostname,
        dhcp_fingerprint=fingerprint,
        dhcp_client_id=client_id,
    )


def observe_mdns(pkt: Packet) -> DeviceObservation | None:
    if not (pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return None
    udp = pkt[UDP]
    if udp.dport != 5353 and udp.sport != 5353:
        return None
    mac = normalize_mac(str(pkt[Ether].src)) if pkt.haslayer(Ether) else None
    if not mac:
        return None
    name = None
    dns = pkt[DNS]
    answers = dns.an if dns.ancount else None
    first = answers[0] if answers else None
    if first is not None:
        name = _as_text(getattr(first, "rrname", None))
        if name:
            name = name.rstrip(".").removesuffix(".local")
    ip = str(pkt[IP].src) if pkt.haslayer(IP) else None
    return DeviceObservation(mac=mac, ip=ip, mdns_name=name)


def observe(pkt: Packet) -> DeviceObservation | None:
    """패킷에서 가능한 관측을 추출한다(ARP → DHCP → mDNS 순)."""
    return observe_arp(pkt) or observe_dhcp(pkt) or observe_mdns(pkt)


def sniff_forever(
    iface: str,
    on_observation: Callable[[DeviceObservation], None],
    bpf: str = "arp or (udp and (port 67 or port 68 or port 5353))",
) -> None:  # pragma: no cover - 라이브 캡처 루프
    from scapy.sendrecv import sniff

    def _cb(pkt: Packet) -> None:
        obs = observe(pkt)
        if obs is not None:
            on_observation(obs)

    sniff(iface=iface, filter=bpf, prn=_cb, store=False)
