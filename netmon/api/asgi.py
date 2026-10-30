"""uvicorn 진입점(팩토리). 서비스에서 환경변수로 DB·정적 번들 경로를 받는다.

바인딩은 uvicorn 실행 인자(127.0.0.1)와 Tailscale Serve(P3.5)에서 강제한다. 앱 자체는
주소를 결정하지 않는다. 인터넷 노출 금지(CC4).

실행 예: uvicorn --factory netmon.api.asgi:make_app --host 127.0.0.1 --port 8080
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from netmon.api.app import DEFAULT_WEB_BUILD, create_app

__all__ = ["make_app"]


def make_app() -> FastAPI:
    db = os.environ.get("NETMON_DB", "/var/lib/netmon/netmon.db")
    web_env = os.environ.get("NETMON_WEB_BUILD")
    web_build: Path | None = Path(web_env) if web_env else DEFAULT_WEB_BUILD
    return create_app(db, web_build=web_build)
