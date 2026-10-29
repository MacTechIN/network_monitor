"""수동 발견 파서: ARP/DHCP/mDNS 패킷에서 기기 관측을 뽑는지 검증한다(직렬화 왕복 포함)."""

from __future__ import annotations

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from netmon.discovery.identity import identify
from netmon.discovery.passive import observe, observe_arp, observe_dhcp, observe_mdns


def test_observe_arp() -> None:
    pkt = Ether(src="b8:27:eb:11:22:33") / ARP(hwsrc="b8:27:eb:11:22:33", psrc="192.168.45.20")
    obs = observe_arp(pkt)
    assert obs is not None
    assert obs.mac == "b8:27:eb:11:22:33"
    assert obs.ip == "192.168.45.20"


def test_observe_dhcp_roundtrip() -> None:
    pkt = (
        Ether(src="02:aa:bb:cc:dd:01")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex("02aabbccdd01"))
        / DHCP(
            options=[
                ("message-type", "request"),
                ("hostname", b"sams-iphone"),
                ("param_req_list", 1, 3, 6, 15, 119, 252),
                ("client_id", b"\x01\x02\xaa\xbb\xcc\xdd\x01"),
                "end",
            ]
        )
    )
    parsed = Ether(bytes(pkt))  # 직렬화 왕복: 실제 파싱 경로를 거친다
    obs = observe_dhcp(parsed)
    assert obs is not None
    assert obs.mac == "02:aa:bb:cc:dd:01"
    assert obs.dhcp_hostname == "sams-iphone"
    assert obs.dhcp_fingerprint == "1,3,6,15,119,252"
    assert obs.dhcp_client_id is not None
    # 랜덤 MAC + 복합 속성 → rnd: 키
    ident = identify(obs)
    assert ident.randomized is True
    assert ident.key.startswith("rnd:")


def test_observe_mdns() -> None:
    pkt = (
        Ether(src="3c:22:fb:00:11:22")
        / IP(src="192.168.45.30", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(
            qr=1,
            ancount=1,
            an=DNSRR(rrname="living-room-tv.local", type="A", rdata="192.168.45.30"),
        )
    )
    parsed = Ether(bytes(pkt))
    obs = observe_mdns(parsed)
    assert obs is not None
    assert obs.mac == "3c:22:fb:00:11:22"
    assert obs.mdns_name == "living-room-tv"


def test_observe_dispatch_and_none() -> None:
    arp = Ether(src="b8:27:eb:11:22:33") / ARP(hwsrc="b8:27:eb:11:22:33", psrc="192.168.45.20")
    assert observe(arp) is not None
    plain = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="1.1.1.1", dst="2.2.2.2")
    assert observe(plain) is None
