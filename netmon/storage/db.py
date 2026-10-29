"""SQLite 저장소: 스키마와 연결 헬퍼 (stdlib sqlite3, WAL).

경량 단계라 ORM 없이 sqlite3 를 직접 쓴다. 스키마는 알림·흐름 메타데이터만 담으며
페이로드/원시 패킷 컬럼은 두지 않는다(정의서 §4 하드 제약: 페이로드 저장 금지).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    flow_id       INTEGER,
    src_ip        TEXT,
    src_port      INTEGER,
    dest_ip       TEXT,
    dest_port     INTEGER,
    proto         TEXT,
    app_proto     TEXT,
    signature     TEXT,
    category      TEXT,
    severity      INTEGER,
    signature_id  INTEGER,
    community_id  TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    flow_id         INTEGER,
    src_ip          TEXT,
    src_port        INTEGER,
    dest_ip         TEXT,
    dest_port       INTEGER,
    proto           TEXT,
    app_proto       TEXT,
    pkts_toserver   INTEGER,
    pkts_toclient   INTEGER,
    bytes_toserver  INTEGER,
    bytes_toclient  INTEGER,
    community_id    TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_flow ON alerts(flow_id);
CREATE INDEX IF NOT EXISTS idx_flows_flow ON flows(flow_id);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    """Open a SQLite connection with WAL and foreign keys enabled."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they do not exist."""
    conn.executescript(SCHEMA)
    conn.commit()
