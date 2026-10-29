"""P3.2: SvelteKit 정적 번들이 FastAPI 에서 서빙되는지 검증한다(ADR-0002).

실제 빌드(web/build)에 의존하지 않도록 임시 빌드 디렉터리로 마운트 동작을 확인한다.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from netmon.api.app import create_app


def _make_build(tmp_path: Path) -> Path:
    build = tmp_path / "build"
    build.mkdir()
    (build / "index.html").write_text("<!doctype html><title>netmon</title>", encoding="utf-8")
    return build


def test_spa_bundle_served_at_root(tmp_path: Path) -> None:
    db = tmp_path / "netmon.db"
    build = _make_build(tmp_path)
    client = TestClient(create_app(db, web_build=build))

    root = client.get("/")
    assert root.status_code == 200
    assert "netmon" in root.text

    # API 라우트는 정적 마운트보다 우선한다.
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/devices").json() == []


def test_api_only_when_no_build(tmp_path: Path) -> None:
    db = tmp_path / "netmon.db"
    client = TestClient(create_app(db, web_build=None))
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/").status_code == 404  # 정적 번들 없음 → API 전용
