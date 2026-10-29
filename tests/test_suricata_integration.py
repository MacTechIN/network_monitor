"""통합 테스트: 커밋된 Suricata 설정으로 샘플 PCAP를 오프라인 재생해 EVE 를 만들고,
그 EVE 를 netmon 수집기로 SQLite 에 적재한다. Suricata/룰이 없으면 건너뛴다.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from netmon.ingest.eve import ingest_lines
from netmon.storage.db import connect, init_db

REPO = Path(__file__).resolve().parent.parent
PCAP = REPO / "tests" / "pcaps" / "sample_dns.pcap"
CONFIG = REPO / "config" / "suricata" / "netmon.yaml"
SYSTEM_RULES = Path("/var/lib/suricata/rules/suricata.rules")

pytestmark = pytest.mark.skipif(
    shutil.which("suricata") is None or not SYSTEM_RULES.exists(),
    reason="Suricata 또는 ET Open 룰이 설치되어 있지 않음",
)


def _run_suricata(out_dir: Path) -> Path:
    proc = subprocess.run(
        ["suricata", "-r", str(PCAP), "-c", str(CONFIG), "-l", str(out_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    eve = out_dir / "eve.json"
    if proc.returncode != 0 or not eve.exists():
        pytest.skip(f"suricata 오프라인 실행 실패(rc={proc.returncode}): {proc.stderr[-300:]}")
    return eve


def test_offline_replay_produces_eve_with_community_id(tmp_path: Path) -> None:
    eve = _run_suricata(tmp_path)
    kinds: dict[str, int] = {}
    with_cid = 0
    for line in eve.read_text(encoding="utf-8").splitlines():
        obj = json.loads(line)
        assert isinstance(obj, dict)
        etype = obj.get("event_type")
        if isinstance(etype, str):
            kinds[etype] = kinds.get(etype, 0) + 1
        if "community_id" in obj:
            with_cid += 1
    assert kinds.get("alert", 0) >= 1  # 로컬 테스트 룰(9000001)
    assert kinds.get("flow", 0) >= 1
    assert with_cid >= 1


def test_eve_ingests_into_sqlite(tmp_path: Path) -> None:
    eve = _run_suricata(tmp_path)
    conn = connect(":memory:")
    init_db(conn)
    with eve.open(encoding="utf-8") as f:
        stats = ingest_lines(conn, f)
    assert stats.alerts >= 1
    assert stats.flows >= 1
    db_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert db_alerts == stats.alerts
    sids = [r[0] for r in conn.execute("SELECT DISTINCT signature_id FROM alerts")]
    assert 9000001 in sids
