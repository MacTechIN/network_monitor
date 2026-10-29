"""흐름을 시간 버킷으로 집계하고 hive 파티션 Parquet(``res=.../date=...``)로 적재한다.

실시간 경로가 적재한 흐름(P1.4, SQLite ``flows``)을 입력으로 받아 기기(src)·목적지(dest)·
프로토콜별 1분(기본) 버킷을 만든다. 배치 경로는 이 집계만 읽는다(정의서 §9 데이터 흐름 규칙).
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import polars as pl

__all__ = [
    "Bucket",
    "FlowInput",
    "aggregate_flows",
    "flows_from_db",
    "read_buckets_parquet",
    "write_buckets_parquet",
]


@dataclass(frozen=True, slots=True)
class FlowInput:
    ts: str
    src_ip: str | None
    dest_ip: str | None
    proto: str | None
    pkts_toserver: int | None
    pkts_toclient: int | None
    bytes_toserver: int | None
    bytes_toclient: int | None


@dataclass(frozen=True, slots=True)
class Bucket:
    bucket_start: str
    src_ip: str | None
    dest_ip: str | None
    proto: str | None
    flow_count: int
    pkts: int
    bytes: int


_Key = tuple[str, str | None, str | None, str | None]


def _floor(ts: str, resolution_s: int) -> datetime:
    dt = datetime.fromisoformat(ts)
    epoch = int(dt.timestamp())
    floored = epoch - (epoch % resolution_s)
    return datetime.fromtimestamp(floored, tz=dt.tzinfo)


def aggregate_flows(flows: Iterable[FlowInput], resolution_s: int = 60) -> list[Bucket]:
    """기기·목적지·프로토콜별로 흐름을 ``resolution_s`` 초 버킷으로 집계한다."""
    counts: dict[_Key, int] = defaultdict(int)
    pkts: dict[_Key, int] = defaultdict(int)
    nbytes: dict[_Key, int] = defaultdict(int)
    for flow in flows:
        start = _floor(flow.ts, resolution_s).isoformat()
        key: _Key = (start, flow.src_ip, flow.dest_ip, flow.proto)
        counts[key] += 1
        pkts[key] += (flow.pkts_toserver or 0) + (flow.pkts_toclient or 0)
        nbytes[key] += (flow.bytes_toserver or 0) + (flow.bytes_toclient or 0)
    return [
        Bucket(
            bucket_start=start,
            src_ip=src,
            dest_ip=dest,
            proto=proto,
            flow_count=counts[key],
            pkts=pkts[key],
            bytes=nbytes[key],
        )
        for key in sorted(counts, key=lambda k: (k[0], k[1] or "", k[2] or "", k[3] or ""))
        for (start, src, dest, proto) in [key]
    ]


def flows_from_db(conn: sqlite3.Connection) -> list[FlowInput]:
    """SQLite ``flows`` 테이블을 :class:`FlowInput` 목록으로 읽는다."""
    rows = conn.execute(
        "SELECT ts, src_ip, dest_ip, proto, pkts_toserver, pkts_toclient, "
        "bytes_toserver, bytes_toclient FROM flows"
    ).fetchall()
    return [
        FlowInput(
            ts=r[0],
            src_ip=r[1],
            dest_ip=r[2],
            proto=r[3],
            pkts_toserver=r[4],
            pkts_toclient=r[5],
            bytes_toserver=r[6],
            bytes_toclient=r[7],
        )
        for r in rows
    ]


def write_buckets_parquet(
    buckets: list[Bucket], base_dir: Path | str, resolution_label: str = "1m"
) -> list[Path]:
    """버킷을 ``base_dir/res=<label>/date=YYYY-MM-DD/part.parquet`` 로 적재한다."""
    base = Path(base_dir)
    by_date: dict[str, list[Bucket]] = defaultdict(list)
    for bucket in buckets:
        by_date[bucket.bucket_start[:10]].append(bucket)
    written: list[Path] = []
    for date, day_buckets in sorted(by_date.items()):
        out_dir = base / f"res={resolution_label}" / f"date={date}"
        out_dir.mkdir(parents=True, exist_ok=True)
        frame = pl.DataFrame([asdict(b) for b in day_buckets])
        path = out_dir / "part-0.parquet"
        frame.write_parquet(path)
        written.append(path)
    return written


def read_buckets_parquet(base_dir: Path | str) -> pl.DataFrame:
    """적재된 버킷 Parquet 전체를 hive 파티션 인식으로 읽는다."""
    base = Path(base_dir)
    return pl.read_parquet(base / "**" / "*.parquet", hive_partitioning=True)
