"""GeoIP/ASN 보강 — 로컬 DB만 사용 (외부 조회 금지, 정의서 §4 / CC4).

1차 데이터원은 iptoasn(PDDL, 키 불필요)의 ``ip2asn-v4.tsv`` / ``ip2asn-v6.tsv`` 이다.
각 행은 ``range_start<TAB>range_end<TAB>ASN<TAB>country<TAB>AS_description`` 이며 ASN·국가를
한 번에 준다. GeoLite2(MaxMind)는 라이선스상 동봉하지 않고(CC2) 사용자 키 opt-in 으로만
얹는다. DB-IP Lite(도시 단위)는 추후 선택 보강으로 같은 조회기 위에 올린다.

조회는 IP 를 정수로 변환해 정렬된 구간을 이진 탐색한다. IPv4/IPv6 은 정수 공간이 겹치므로
버전별로 분리해 보관한다. 사설·예약 주소(is_global=False)는 태깅하지 않는다(None 반환).
"""

from __future__ import annotations

import bisect
import ipaddress
from dataclasses import dataclass
from pathlib import Path

__all__ = ["GeoAsn", "IpAsnLookup"]


@dataclass(frozen=True, slots=True)
class GeoAsn:
    asn: int | None
    country: str | None
    as_description: str | None


@dataclass(frozen=True, slots=True)
class _Ranges:
    """버전 하나의 정렬된 구간: starts[i] 시작, ends[i] 끝, data[i] 보강값."""

    starts: list[int]
    ends: list[int]
    data: list[GeoAsn]

    def lookup(self, value: int) -> GeoAsn | None:
        i = bisect.bisect_right(self.starts, value) - 1
        if i < 0 or value > self.ends[i]:
            return None
        return self.data[i]


class IpAsnLookup:
    def __init__(self, v4: _Ranges, v6: _Ranges) -> None:
        self._v4 = v4
        self._v6 = v6

    @classmethod
    def from_iptoasn_tsv(cls, *paths: Path | str) -> IpAsnLookup:
        """iptoasn TSV 하나 이상(v4·v6)을 로드한다."""
        rows4: list[tuple[int, int, GeoAsn]] = []
        rows6: list[tuple[int, int, GeoAsn]] = []
        for path in paths:
            for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.rstrip("\n")
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 5:
                    continue
                try:
                    start = ipaddress.ip_address(parts[0].strip())
                    end = ipaddress.ip_address(parts[1].strip())
                    asn_raw = int(parts[2].strip())
                except ValueError:
                    continue
                if start.version != end.version:
                    continue
                country = parts[3].strip() or None
                desc = parts[4].strip() or None
                # ASN 0 = 미라우팅. country "None"/"ZZ" 등은 그대로 두되 빈 값만 None.
                geo = GeoAsn(asn=asn_raw or None, country=country, as_description=desc)
                target = rows4 if start.version == 4 else rows6
                target.append((int(start), int(end), geo))
        return cls(cls._build(rows4), cls._build(rows6))

    @staticmethod
    def _build(rows: list[tuple[int, int, GeoAsn]]) -> _Ranges:
        rows.sort(key=lambda r: r[0])
        return _Ranges(
            starts=[r[0] for r in rows],
            ends=[r[1] for r in rows],
            data=[r[2] for r in rows],
        )

    @classmethod
    def empty(cls) -> IpAsnLookup:
        """DB 가 없을 때 쓰는 빈 조회기(모든 조회가 None)."""
        empty = _Ranges([], [], [])
        return cls(empty, empty)

    def lookup(self, ip: str) -> GeoAsn | None:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        if not addr.is_global:  # 사설·예약·루프백은 태깅하지 않음
            return None
        ranges = self._v4 if addr.version == 4 else self._v6
        return ranges.lookup(int(addr))
