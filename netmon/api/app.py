"""FastAPI 앱: 기기·알림·사건 조회 (M3 대시보드 백엔드).

localhost/Tailscale 에만 바인딩해 운영한다. 바인딩 제한은 배포(uvicorn --host)와
Tailscale Serve(P3.5)에서 강제하고, 앱은 인증을 Tailscale identity header 에 위임한다
(정의서 §4: 인터넷 노출 금지, CC4).

읽기 경로는 단일 워커·가벼운 조회라 stdlib sqlite3 를 동기 엔드포인트(스레드풀 실행)로
직접 쓴다. 계획서 P3.1 은 aiosqlite 를 언급하나, 동시성 이득이 없어 의존성을 더하지 않고
동기 경로로 유지한다(실시간 탐지 경로와 분리되어 성능 영향 없음).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import FastAPI, Query
from pydantic import BaseModel

from netmon.storage.db import connect, init_db

__all__ = ["Alert", "Device", "Incident", "create_app"]


class Device(BaseModel):
    key: str
    label: str | None = None
    randomized: int
    mac: str | None = None
    ip: str | None = None
    vendor: str | None = None
    first_seen: str
    last_seen: str


class Alert(BaseModel):
    id: int
    ts: str
    flow_id: int | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    app_proto: str | None = None
    signature: str | None = None
    category: str | None = None
    severity: int | None = None
    signature_id: int | None = None
    community_id: str | None = None


class Incident(BaseModel):
    id: int
    created_ts: str
    severity: int | None = None
    title: str | None = None
    status: str
    device_key: str | None = None


def _rows(path: str, sql: str, params: tuple[object, ...]) -> list[sqlite3.Row]:
    conn = connect(path)
    init_db(conn)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def create_app(db_path: Path | str) -> FastAPI:
    app = FastAPI(title="netmon", version="0.0.1")
    path = str(db_path)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/devices", response_model=list[Device])
    def list_devices() -> list[dict[str, object]]:
        rows = _rows(
            path,
            "SELECT key, label, randomized, mac, ip, vendor, first_seen, last_seen "
            "FROM devices ORDER BY last_seen DESC",
            (),
        )
        return [dict(r) for r in rows]

    @app.get("/alerts", response_model=list[Alert])
    def list_alerts(limit: int = Query(default=100, ge=1, le=1000)) -> list[dict[str, object]]:
        rows = _rows(
            path,
            "SELECT id, ts, flow_id, src_ip, src_port, dest_ip, dest_port, proto, "
            "app_proto, signature, category, severity, signature_id, community_id "
            "FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    @app.get("/incidents", response_model=list[Incident])
    def list_incidents(limit: int = Query(default=100, ge=1, le=1000)) -> list[dict[str, object]]:
        rows = _rows(
            path,
            "SELECT id, created_ts, severity, title, status, device_key "
            "FROM incidents ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    return app
