"""FastAPI 앱: 기기/알림 조회 (M3 에서 확장). localhost/Tailscale 에만 바인딩해 운영한다.

바인딩 제한은 배포(uvicorn --host)와 Tailscale Serve(P3.5)에서 강제한다. 앱 자체는
인증을 Tailscale identity header 에 위임한다(정의서 §4: 인터넷 노출 금지).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from netmon.storage.db import connect, init_db

__all__ = ["create_app"]


def create_app(db_path: Path | str) -> FastAPI:
    app = FastAPI(title="netmon", version="0.0.1")
    path = str(db_path)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/devices")
    def list_devices() -> list[dict[str, object]]:
        conn = connect(path)
        init_db(conn)
        try:
            rows = conn.execute(
                "SELECT key, label, randomized, mac, ip, vendor, first_seen, last_seen "
                "FROM devices ORDER BY last_seen DESC"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    return app
