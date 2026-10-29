"""복합 기기 신원 (정의서 §11, tech_research §6.2 #3).

스마트폰은 SSID마다 랜덤(로컬 관리) MAC을 쓰므로 MAC 단일 키로는 같은 기기가 매번 새
기기로 잡혀 FR-8 새 기기 알림이 오탐 폭주한다. 전역 고유 MAC이면 MAC을 키로 쓰고,
랜덤 MAC이면 (DHCP 지문·호스트명·client-id·mDNS 이름) 복합 속성으로 기기를 추적한다.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = [
    "DeviceIdentity",
    "DeviceObservation",
    "identify",
    "is_randomized_mac",
    "merge_identities",
    "normalize_mac",
]


@dataclass(frozen=True, slots=True)
class DeviceObservation:
    mac: str
    ip: str | None = None
    dhcp_hostname: str | None = None
    dhcp_fingerprint: str | None = None  # DHCP option 55 (parameter request list)
    dhcp_client_id: str | None = None
    mdns_name: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    key: str
    randomized: bool
    label: str


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def is_randomized_mac(mac: str) -> bool:
    """로컬 관리(LAA) 비트가 켜져 있으면 랜덤/로컬 MAC 으로 본다."""
    first_octet = int(normalize_mac(mac).split(":")[0], 16)
    return bool(first_octet & 0b10)


def _composite(obs: DeviceObservation) -> str:
    parts = [
        obs.dhcp_fingerprint,
        obs.dhcp_hostname,
        obs.dhcp_client_id,
        obs.mdns_name,
    ]
    return "|".join(p for p in parts if p)


def identify(obs: DeviceObservation) -> DeviceIdentity:
    """관측에서 안정적인 기기 신원을 계산한다."""
    mac = normalize_mac(obs.mac)
    label = obs.dhcp_hostname or obs.mdns_name or mac
    if not is_randomized_mac(mac):
        return DeviceIdentity(key=f"mac:{mac}", randomized=False, label=label)
    composite = _composite(obs)
    if not composite:
        # 랜덤 MAC 인데 식별 속성이 없으면 MAC 으로 폴백(최선). randomized 로 표시.
        return DeviceIdentity(key=f"mac:{mac}", randomized=True, label=label)
    digest = hashlib.sha1(composite.encode("utf-8")).hexdigest()[:16]
    return DeviceIdentity(key=f"rnd:{digest}", randomized=True, label=label)


def merge_identities(keep: DeviceIdentity, other: DeviceIdentity) -> DeviceIdentity:
    """수동 병합: 두 신원을 같은 기기로 합친다(``keep`` 키 유지)."""
    return DeviceIdentity(
        key=keep.key,
        randomized=keep.randomized or other.randomized,
        label=keep.label or other.label,
    )
