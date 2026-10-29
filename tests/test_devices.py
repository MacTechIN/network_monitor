"""기기 저장소와 API: 신규 탐지(FR-8)와 /devices 조회를 검증한다."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from netmon.api.app import create_app
from netmon.discovery.identity import DeviceObservation
from netmon.discovery.store import record_observation
from netmon.enrich.oui import OUILookup
from netmon.storage.db import connect, init_db

FIXTURE_OUI = Path(__file__).resolve().parent / "fixtures" / "ieee-oui-sample.txt"


def test_new_device_then_not_new() -> None:
    conn = connect(":memory:")
    init_db(conn)
    oui = OUILookup.from_ieee_oui_txt(FIXTURE_OUI)
    obs = DeviceObservation(mac="b8:27:eb:11:22:33", ip="192.168.45.20", dhcp_hostname="pi")

    ident, is_new = record_observation(conn, obs, oui=oui, now="2026-10-30T00:00:00+00:00")
    assert is_new is True
    assert ident.key == "mac:b8:27:eb:11:22:33"

    _, is_new2 = record_observation(conn, obs, oui=oui, now="2026-10-30T01:00:00+00:00")
    assert is_new2 is False
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    row = conn.execute("SELECT vendor, last_seen FROM devices").fetchone()
    assert row["vendor"] == "Raspberry Pi Foundation"
    assert row["last_seen"] == "2026-10-30T01:00:00+00:00"


def test_randomized_phone_not_flagged_twice() -> None:
    conn = connect(":memory:")
    init_db(conn)
    common = {"dhcp_fingerprint": "1,3,6,15", "dhcp_hostname": "phone"}
    _, new1 = record_observation(conn, DeviceObservation(mac="02:aa:bb:cc:dd:01", **common))
    _, new2 = record_observation(conn, DeviceObservation(mac="06:11:22:33:44:99", **common))
    assert new1 is True
    assert new2 is False  # 다른 랜덤 MAC 이지만 같은 기기 → 새 기기 아님
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_api_healthz_and_devices(tmp_path: Path) -> None:
    db = tmp_path / "netmon.db"
    conn = connect(db)
    init_db(conn)
    record_observation(
        conn, DeviceObservation(mac="3c:22:fb:00:11:22", ip="192.168.45.30", mdns_name="tv")
    )
    conn.close()
    client = TestClient(create_app(db))
    assert client.get("/healthz").json() == {"status": "ok"}
    devices = client.get("/devices").json()
    assert len(devices) == 1
    assert devices[0]["mac"] == "3c:22:fb:00:11:22"
    assert devices[0]["label"] == "tv"


def test_api_alerts_and_incidents(tmp_path: Path) -> None:
    db = tmp_path / "netmon.db"
    conn = connect(db)
    init_db(conn)
    conn.execute(
        "INSERT INTO alerts (ts, signature, severity, src_ip, dest_ip) VALUES (?,?,?,?,?)",
        ("2026-10-30T00:00:00+00:00", "ET TEST rule", 2, "192.168.45.30", "203.0.113.5"),
    )
    conn.execute(
        "INSERT INTO incidents (created_ts, severity, title, status, device_key) "
        "VALUES (?,?,?,?,?)",
        ("2026-10-30T00:05:00+00:00", 3, "의심 비컨", "open", "mac:3c:22:fb:00:11:22"),
    )
    conn.commit()
    conn.close()

    client = TestClient(create_app(db))

    alerts = client.get("/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["signature"] == "ET TEST rule"
    assert alerts[0]["severity"] == 2

    incidents = client.get("/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "의심 비컨"
    assert incidents[0]["status"] == "open"

    # limit 경계: 상한 초과는 422
    assert client.get("/alerts", params={"limit": 5000}).status_code == 422


def test_api_empty_tables_return_empty_lists(tmp_path: Path) -> None:
    db = tmp_path / "netmon.db"
    client = TestClient(create_app(db))  # DB 파일은 첫 조회 시 생성됨
    assert client.get("/alerts").json() == []
    assert client.get("/incidents").json() == []
    assert client.get("/devices").json() == []
