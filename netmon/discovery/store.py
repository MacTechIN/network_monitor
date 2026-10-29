"""기기 저장소: 관측을 복합 신원으로 묶어 devices 테이블에 upsert 하고 신규 여부를 알린다.

관측(P2.1) → 신원(P2.2) → 벤더(P2.3) 를 결합한다. 처음 보는 신원 키일 때 ``is_new`` 가
True 이며, 이것이 FR-8 새 기기 알림(P2.5)의 트리거다(랜덤 MAC 오탐은 복합 신원이 흡수).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from netmon.discovery.identity import DeviceIdentity, DeviceObservation, identify
from netmon.enrich.oui import OUILookup

__all__ = ["record_observation"]


def record_observation(
    conn: sqlite3.Connection,
    obs: DeviceObservation,
    oui: OUILookup | None = None,
    now: str | None = None,
) -> tuple[DeviceIdentity, bool]:
    """관측을 기록하고 (신원, 신규여부) 를 반환한다."""
    ident = identify(obs)
    vendor = oui.vendor(obs.mac) if oui is not None else None
    ts = now or datetime.now(UTC).isoformat()
    existing = conn.execute("SELECT key FROM devices WHERE key = ?", (ident.key,)).fetchone()
    is_new = existing is None
    if is_new:
        conn.execute(
            "INSERT INTO devices (key, label, randomized, mac, ip, vendor, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ident.key, ident.label, int(ident.randomized), obs.mac, obs.ip, vendor, ts, ts),
        )
    else:
        conn.execute(
            "UPDATE devices SET label=?, mac=?, ip=COALESCE(?, ip), "
            "vendor=COALESCE(?, vendor), last_seen=? WHERE key=?",
            (ident.label, obs.mac, obs.ip, vendor, ts, ident.key),
        )
    conn.commit()
    return ident, is_new
