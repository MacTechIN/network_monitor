"""eve.json 를 따라가며(tail) 새로 쌓인 줄만 SQLite 에 적재하는 수집 데몬.

Suricata 가 쓰는 EVE 로그를 폴링해 완전한 줄(개행으로 끝난)만 처리하고 바이트 오프셋을
기록한다. 부분 줄은 다음 폴링까지 남겨 둔다. systemd 유닛(netmon-ingest.service)의 진입점.
"""

from __future__ import annotations

import argparse
import sqlite3
import time
from pathlib import Path

from netmon.ingest.eve import IngestStats, ingest_lines
from netmon.storage.db import connect, init_db

__all__ = ["follow", "main", "process_available"]


def process_available(
    conn: sqlite3.Connection, path: Path | str, offset: int
) -> tuple[int, IngestStats]:
    """``offset`` 이후의 완전한 줄만 적재하고 (새 오프셋, 통계) 를 반환한다."""
    data = Path(path).read_bytes()[offset:]
    if not data:
        return offset, IngestStats()
    last_nl = data.rfind(b"\n")
    if last_nl == -1:
        return offset, IngestStats()
    chunk = data[: last_nl + 1].decode("utf-8", errors="replace")
    stats = ingest_lines(conn, chunk.splitlines())
    return offset + last_nl + 1, stats


def follow(
    conn: sqlite3.Connection, path: Path | str, poll_s: float = 1.0
) -> None:  # pragma: no cover - 무한 루프
    """``path`` 를 폴링하며 새 줄을 계속 적재한다 (systemd 가 수명을 관리)."""
    offset = 0
    while True:
        if Path(path).exists():
            offset, _ = process_available(conn, path, offset)
        time.sleep(poll_s)


def main() -> int:  # pragma: no cover - 얇은 CLI 래퍼
    parser = argparse.ArgumentParser(description="EVE JSON → SQLite tail 수집기")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json")
    parser.add_argument("--db", default="/var/lib/netmon/netmon.db")
    parser.add_argument("--poll", type=float, default=1.0)
    args = parser.parse_args()
    conn = connect(args.db)
    init_db(conn)
    follow(conn, args.eve, args.poll)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
