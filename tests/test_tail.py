"""tail 수집기: 오프셋 추적으로 새 줄만, 부분 줄은 보류하며 적재하는지 검증한다."""

from __future__ import annotations

from pathlib import Path

from netmon.ingest.tail import process_available
from netmon.storage.db import connect, init_db

ALERT = (
    '{"timestamp":"2026-10-30T12:00:00+09:00","event_type":"alert","flow_id":%d,'
    '"alert":{"signature":"x","severity":1,"signature_id":%d}}\n'
)


def test_processes_only_complete_lines_and_tracks_offset(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    conn = connect(":memory:")
    init_db(conn)

    # 완전한 줄 2개 + 부분 줄 1개
    eve.write_text((ALERT % (1, 1001)) + (ALERT % (2, 1002)) + '{"partial":', encoding="utf-8")
    offset, stats = process_available(conn, eve, 0)
    assert stats.alerts == 2
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2

    # 같은 오프셋에서 다시 호출 → 부분 줄뿐이라 추가 적재 없음
    offset2, stats2 = process_available(conn, eve, offset)
    assert stats2.alerts == 0
    assert offset2 == offset

    # 부분 줄이 완성되고 새 줄 추가 → 이어서 적재
    with eve.open("a", encoding="utf-8") as f:
        f.write('"done":true}\n' + (ALERT % (3, 1003)))
    _, stats3 = process_available(conn, eve, offset)
    # 완성된 partial 줄은 유효 JSON/alert 가 아니라 skip, 새 alert 1건만 적재 → 총 3건
    assert stats3.alerts == 1
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3
