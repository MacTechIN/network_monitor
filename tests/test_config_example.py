"""config/netmon.example.yaml 이 하드 제약(정의서 §4·§8)을 기본값으로 담는지 검증한다."""

from __future__ import annotations

from pathlib import Path

import yaml

EXAMPLE = Path(__file__).resolve().parent.parent / "config" / "netmon.example.yaml"


def _load() -> dict[str, object]:
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_example_exists_and_parses() -> None:
    assert EXAMPLE.is_file()
    assert _load()


def test_notice_ack_is_first_key_and_off() -> None:
    data = _load()
    assert next(iter(data)) == "monitoring_notice_acknowledged"
    assert data["monitoring_notice_acknowledged"] is False


def test_conservative_defaults() -> None:
    data = _load()
    active_scan = data["active_scan"]
    storage = data["storage"]
    external = data["external_transmission"]
    assert isinstance(active_scan, dict) and active_scan["enabled"] is False
    assert isinstance(storage, dict) and storage["payload_storage"] is False
    assert isinstance(external, dict) and external["enabled"] is False


def test_no_spoofing_and_no_internet_exposure() -> None:
    data = _load()
    capture = data["capture"]
    dashboard = data["dashboard"]
    assert isinstance(capture, dict)
    assert capture["visibility_mode"] in {"passive", "gateway"}
    assert isinstance(dashboard, dict)
    assert dashboard["bind"] in {"localhost", "tailscale"}
