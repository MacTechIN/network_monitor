"""복합 기기 신원: 랜덤 MAC 판별과 같은 기기 병합(오탐 방지)을 검증한다."""

from __future__ import annotations

from netmon.discovery.identity import (
    DeviceObservation,
    identify,
    is_randomized_mac,
    merge_identities,
    normalize_mac,
)


def test_normalize_mac() -> None:
    assert normalize_mac("B8-27-EB-01-02-03") == "b8:27:eb:01:02:03"


def test_randomized_mac_detection() -> None:
    # 전역 고유(OUI): LAA 비트 0
    assert is_randomized_mac("b8:27:eb:11:22:33") is False  # Raspberry Pi
    assert is_randomized_mac("3c:22:fb:00:11:22") is False
    # 로컬 관리(랜덤): LAA 비트 1 (02, 06, 0a, aa ...)
    assert is_randomized_mac("02:11:22:33:44:55") is True
    assert is_randomized_mac("aa:bb:cc:dd:ee:ff") is True
    assert is_randomized_mac("de:ad:be:ef:00:01") is True


def test_global_mac_keys_on_mac() -> None:
    obs = DeviceObservation(mac="b8:27:eb:11:22:33", dhcp_hostname="pi")
    ident = identify(obs)
    assert ident.key == "mac:b8:27:eb:11:22:33"
    assert ident.randomized is False
    assert ident.label == "pi"


def test_randomized_same_device_same_key() -> None:
    # 같은 폰이 SSID마다 다른 랜덤 MAC을 쓰지만 DHCP 지문·호스트명은 같다.
    common = {
        "dhcp_fingerprint": "1,3,6,15,119,252",
        "dhcp_hostname": "sams-iphone",
    }
    a = identify(DeviceObservation(mac="02:aa:bb:cc:dd:01", **common))
    b = identify(DeviceObservation(mac="06:11:22:33:44:99", **common))
    assert a.randomized and b.randomized
    assert a.key == b.key  # 새 기기로 오탐되지 않는다
    assert a.key.startswith("rnd:")


def test_randomized_different_devices_differ() -> None:
    a = identify(
        DeviceObservation(mac="02:aa:bb:cc:dd:01", dhcp_fingerprint="1,3,6", dhcp_hostname="iphone")
    )
    b = identify(
        DeviceObservation(
            mac="02:aa:bb:cc:dd:01", dhcp_fingerprint="1,3,6,15", dhcp_hostname="android"
        )
    )
    assert a.key != b.key


def test_randomized_without_attributes_falls_back_to_mac() -> None:
    ident = identify(DeviceObservation(mac="02:11:22:33:44:55"))
    assert ident.randomized is True
    assert ident.key == "mac:02:11:22:33:44:55"


def test_manual_merge() -> None:
    a = identify(DeviceObservation(mac="02:aa:bb:cc:dd:01", dhcp_hostname="phone"))
    b = identify(DeviceObservation(mac="b8:27:eb:11:22:33", dhcp_hostname="phone-wifi"))
    merged = merge_identities(a, b)
    assert merged.key == a.key
    assert merged.randomized is True
