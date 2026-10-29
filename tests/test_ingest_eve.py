"""EVE 수집기: 알림·흐름이 SQLite 에 정확히 적재되고 페이로드는 저장되지 않는지 검증한다."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from netmon.ingest.eve import EveAlert, EveFlow, ingest_lines, parse_line
from netmon.storage.db import connect, init_db

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "eve_sample.jsonl"


def _db() -> sqlite3.Connection:
    conn = connect(":memory:")
    init_db(conn)
    return conn


def test_fixture_counts_match() -> None:
    conn = _db()
    with FIXTURE.open(encoding="utf-8") as f:
        stats = ingest_lines(conn, f)
    # 픽스처: 알림 2, 흐름 2, 건너뜀 2 (dns, stats)
    assert (stats.alerts, stats.flows, stats.skipped) == (2, 2, 2)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2


def test_alert_fields_parsed() -> None:
    conn = _db()
    with FIXTURE.open(encoding="utf-8") as f:
        ingest_lines(conn, f)
    row = conn.execute(
        "SELECT signature, severity, signature_id, community_id FROM alerts WHERE flow_id=1001"
    ).fetchone()
    assert row["signature"] == "ET MALWARE Observed Suspicious TLS"
    assert row["severity"] == 1
    assert row["signature_id"] == 2027000
    assert row["community_id"].startswith("1:")


def test_flow_fields_parsed() -> None:
    conn = _db()
    with FIXTURE.open(encoding="utf-8") as f:
        ingest_lines(conn, f)
    row = conn.execute(
        "SELECT pkts_toserver, bytes_toclient FROM flows WHERE flow_id=1001"
    ).fetchone()
    assert row["pkts_toserver"] == 12
    assert row["bytes_toclient"] == 8200


def test_payload_is_never_stored() -> None:
    # 하드 제약: 스키마에 payload/packet 컬럼이 없어야 하고, 입력의 payload 는 무시된다.
    conn = _db()
    cols_alerts = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert "payload" not in cols_alerts
    assert "packet" not in cols_alerts
    record = parse_line(FIXTURE.read_text(encoding="utf-8").splitlines()[0])
    assert isinstance(record, EveAlert)  # 페이로드가 있어도 알림으로 파싱되고 payload 는 버려진다


def test_parse_line_skips_and_types() -> None:
    assert parse_line("") is None
    assert parse_line("not json") is None
    assert parse_line('{"event_type":"dns","timestamp":"t"}') is None
    assert parse_line('{"event_type":"alert"}') is None  # timestamp 없음 → skip
    alert = parse_line(
        '{"event_type":"alert","timestamp":"t","alert":{"signature":"x","severity":3}}'
    )
    assert isinstance(alert, EveAlert) and alert.severity == 3
    flow = parse_line('{"event_type":"flow","timestamp":"t","flow":{"pkts_toserver":9}}')
    assert isinstance(flow, EveFlow) and flow.pkts_toserver == 9
