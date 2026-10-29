"""흐름 → 1분 버킷 집계와 Parquet 적재: 합계 불변식과 hive 파티션을 검증한다."""

from __future__ import annotations

from pathlib import Path

from netmon.ingest.eve import ingest_lines
from netmon.storage.db import connect, init_db
from netmon.timeseries.buckets import (
    Bucket,
    FlowInput,
    aggregate_flows,
    flows_from_db,
    read_buckets_parquet,
    rollup_buckets,
    write_buckets_parquet,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "eve_sample.jsonl"


def _sample_flows() -> list[FlowInput]:
    # 같은 (src,dest,proto) 를 한 1분 버킷으로 묶이게, 그리고 다른 버킷 하나.
    return [
        FlowInput(
            "2026-10-30T12:00:05+09:00", "192.168.45.10", "203.0.113.5", "TCP", 3, 2, 300, 700
        ),
        FlowInput(
            "2026-10-30T12:00:40+09:00", "192.168.45.10", "203.0.113.5", "TCP", 1, 1, 100, 200
        ),
        FlowInput(
            "2026-10-30T12:01:10+09:00", "192.168.45.10", "203.0.113.5", "TCP", 5, 4, 500, 900
        ),
    ]


def test_minute_bucketing_and_sum_invariant() -> None:
    flows = _sample_flows()
    buckets = aggregate_flows(flows, resolution_s=60)
    # 12:00 버킷(흐름 2개)과 12:01 버킷(흐름 1개) = 2개 버킷
    assert len(buckets) == 2
    first = buckets[0]
    assert first.bucket_start.startswith("2026-10-30T12:00:00")
    assert first.flow_count == 2
    assert first.pkts == 3 + 2 + 1 + 1
    assert first.bytes == 300 + 700 + 100 + 200
    # 불변식: 버킷 합계 == 원본 흐름 합계
    total_in = sum((f.bytes_toserver or 0) + (f.bytes_toclient or 0) for f in flows)
    total_out = sum(b.bytes for b in buckets)
    assert total_in == total_out


def test_write_and_read_parquet_hive(tmp_path: Path) -> None:
    buckets = aggregate_flows(_sample_flows())
    written = write_buckets_parquet(buckets, tmp_path, resolution_label="1m")
    assert written and all(p.exists() for p in written)
    # hive 경로 구조 확인
    assert (tmp_path / "res=1m" / "date=2026-10-30").is_dir()
    frame = read_buckets_parquet(tmp_path)
    assert frame.height == len(buckets)
    assert int(frame["bytes"].sum()) == sum(b.bytes for b in buckets)
    # hive 파티션 컬럼이 복원됨
    assert "res" in frame.columns and "date" in frame.columns


def test_end_to_end_from_ingested_flows(tmp_path: Path) -> None:
    conn = connect(":memory:")
    init_db(conn)
    with FIXTURE.open(encoding="utf-8") as f:
        ingest_lines(conn, f)
    flows = flows_from_db(conn)
    assert len(flows) == 2  # 픽스처 흐름 2개
    buckets = aggregate_flows(flows)
    write_buckets_parquet(buckets, tmp_path)
    frame = read_buckets_parquet(tmp_path)
    assert frame.height == len(buckets)
    # 적재된 바이트 합 == 픽스처 흐름 바이트 합
    expected = sum((f.bytes_toserver or 0) + (f.bytes_toclient or 0) for f in flows)
    assert int(frame["bytes"].sum()) == expected


def test_rollup_1m_to_5m_and_1h() -> None:
    minute = [
        Bucket("2026-10-30T12:00:00+09:00", "A", "B", "TCP", 2, 10, 1000),
        Bucket("2026-10-30T12:02:00+09:00", "A", "B", "TCP", 1, 5, 500),
        Bucket("2026-10-30T12:07:00+09:00", "A", "B", "TCP", 3, 9, 900),
    ]
    five = rollup_buckets(minute, resolution_s=300)
    # 12:00 과 12:02 는 같은 5분 버킷(12:00), 12:07 은 다른 5분 버킷(12:05)
    assert len(five) == 2
    assert five[0].bucket_start.startswith("2026-10-30T12:00:00")
    assert five[0].flow_count == 3  # 2 + 1 (버킷 수가 아니라 흐름 수의 합)
    assert five[0].bytes == 1500
    # 합계 불변식: 롤업해도 총합 보존
    assert sum(b.bytes for b in five) == sum(b.bytes for b in minute)

    hour = rollup_buckets(minute, resolution_s=3600)
    assert len(hour) == 1
    assert hour[0].flow_count == 6
    assert hour[0].bytes == sum(b.bytes for b in minute)
