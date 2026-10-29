"""Suricata EVE JSON 수집: 한 줄씩 파싱해 알림·흐름 메타데이터를 SQLite 에 적재한다.

페이로드/원시 패킷 필드(``payload``, ``packet``)는 입력에 있어도 읽지도 저장하지도
않는다(정의서 §4). ``alert``·``flow`` 외의 이벤트(dns, tls 등)는 이 단계에서 건너뛴다.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass

__all__ = ["EveAlert", "EveFlow", "IngestStats", "ingest_lines", "parse_line"]


@dataclass(frozen=True, slots=True)
class EveAlert:
    ts: str
    flow_id: int | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    proto: str | None
    app_proto: str | None
    signature: str | None
    category: str | None
    severity: int | None
    signature_id: int | None
    community_id: str | None


@dataclass(frozen=True, slots=True)
class EveFlow:
    ts: str
    flow_id: int | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    proto: str | None
    app_proto: str | None
    pkts_toserver: int | None
    pkts_toclient: int | None
    bytes_toserver: int | None
    bytes_toclient: int | None
    community_id: str | None


@dataclass
class IngestStats:
    alerts: int = 0
    flows: int = 0
    skipped: int = 0


def _s(d: dict[str, object], key: str) -> str | None:
    v = d.get(key)
    return v if isinstance(v, str) else None


def _i(d: dict[str, object], key: str) -> int | None:
    v = d.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _sub(d: dict[str, object], key: str) -> dict[str, object]:
    v = d.get(key)
    return v if isinstance(v, dict) else {}


def parse_line(line: str) -> EveAlert | EveFlow | None:
    """Parse one EVE JSON line into a typed record, or ``None`` to skip it.

    Payload/packet fields are never read. Malformed JSON, non-dict events, and
    event types other than ``alert``/``flow`` return ``None``.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    event_type = _s(obj, "event_type")
    ts = _s(obj, "timestamp")
    if ts is None:
        return None
    if event_type == "alert":
        a = _sub(obj, "alert")
        return EveAlert(
            ts=ts,
            flow_id=_i(obj, "flow_id"),
            src_ip=_s(obj, "src_ip"),
            src_port=_i(obj, "src_port"),
            dest_ip=_s(obj, "dest_ip"),
            dest_port=_i(obj, "dest_port"),
            proto=_s(obj, "proto"),
            app_proto=_s(obj, "app_proto"),
            signature=_s(a, "signature"),
            category=_s(a, "category"),
            severity=_i(a, "severity"),
            signature_id=_i(a, "signature_id"),
            community_id=_s(obj, "community_id"),
        )
    if event_type == "flow":
        f = _sub(obj, "flow")
        return EveFlow(
            ts=ts,
            flow_id=_i(obj, "flow_id"),
            src_ip=_s(obj, "src_ip"),
            src_port=_i(obj, "src_port"),
            dest_ip=_s(obj, "dest_ip"),
            dest_port=_i(obj, "dest_port"),
            proto=_s(obj, "proto"),
            app_proto=_s(obj, "app_proto"),
            pkts_toserver=_i(f, "pkts_toserver"),
            pkts_toclient=_i(f, "pkts_toclient"),
            bytes_toserver=_i(f, "bytes_toserver"),
            bytes_toclient=_i(f, "bytes_toclient"),
            community_id=_s(obj, "community_id"),
        )
    return None


def ingest_lines(conn: sqlite3.Connection, lines: Iterable[str]) -> IngestStats:
    """Parse and insert EVE lines, returning counts of alerts/flows/skipped."""
    stats = IngestStats()
    for line in lines:
        record = parse_line(line)
        if isinstance(record, EveAlert):
            conn.execute(
                "INSERT INTO alerts (ts, flow_id, src_ip, src_port, dest_ip, dest_port, "
                "proto, app_proto, signature, category, severity, signature_id, community_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.ts,
                    record.flow_id,
                    record.src_ip,
                    record.src_port,
                    record.dest_ip,
                    record.dest_port,
                    record.proto,
                    record.app_proto,
                    record.signature,
                    record.category,
                    record.severity,
                    record.signature_id,
                    record.community_id,
                ),
            )
            stats.alerts += 1
        elif isinstance(record, EveFlow):
            conn.execute(
                "INSERT INTO flows (ts, flow_id, src_ip, src_port, dest_ip, dest_port, "
                "proto, app_proto, pkts_toserver, pkts_toclient, bytes_toserver, "
                "bytes_toclient, community_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.ts,
                    record.flow_id,
                    record.src_ip,
                    record.src_port,
                    record.dest_ip,
                    record.dest_port,
                    record.proto,
                    record.app_proto,
                    record.pkts_toserver,
                    record.pkts_toclient,
                    record.bytes_toserver,
                    record.bytes_toclient,
                    record.community_id,
                ),
            )
            stats.flows += 1
        else:
            stats.skipped += 1
    conn.commit()
    return stats
