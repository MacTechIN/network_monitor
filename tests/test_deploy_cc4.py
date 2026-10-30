"""P3.5: 대시보드 노출이 CC4(인터넷 미노출)를 위반하지 않는지 배포 산출물로 검증한다.

API 유닛은 localhost 에만 바인딩하고, Serve 스크립트는 Tailscale Serve 만 쓰며 Funnel(공개
노출)을 켜지 않아야 한다. 코드가 아닌 운영 산출물에 대한 회귀 가드다.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API_UNIT = ROOT / "systemd" / "netmon-api.service"
SERVE_SH = ROOT / "scripts" / "serve_dashboard.sh"


def test_api_unit_binds_localhost_only() -> None:
    text = API_UNIT.read_text(encoding="utf-8")
    exec_lines = [ln for ln in text.splitlines() if ln.startswith("ExecStart=")]
    assert exec_lines, "ExecStart 없음"
    assert any("--host 127.0.0.1" in ln for ln in exec_lines)
    assert all("0.0.0.0" not in ln for ln in exec_lines)  # 공개 바인딩 금지
    assert "NoNewPrivileges=true" in text


def test_serve_script_uses_serve_not_funnel() -> None:
    text = SERVE_SH.read_text(encoding="utf-8")
    assert "tailscale serve" in text
    # Funnel 언급은 반드시 끄기/상태 조회 형태여야 한다(공개 노출 금지).
    for line in text.splitlines():
        if "tailscale funnel" in line:
            assert ("off" in line) or ("status" in line), f"Funnel 활성 가능 라인: {line}"
    # 명백한 활성 형태가 없어야 한다.
    assert "funnel --https=443 on" not in text
    assert "funnel --bg" not in text
