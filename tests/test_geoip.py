"""P4.1 GeoIP/ASN 보강: 로컬 iptoasn TSV 로 ASN·국가 태깅, 키 없이·외부 조회 없이 동작."""

from __future__ import annotations

from pathlib import Path

from netmon.enrich.geoip import IpAsnLookup

FIX = Path(__file__).resolve().parent / "fixtures"
V4 = FIX / "ip2asn-v4-sample.tsv"
V6 = FIX / "ip2asn-v6-sample.tsv"


def test_lookup_tags_asn_and_country() -> None:
    gi = IpAsnLookup.from_iptoasn_tsv(V4)
    g = gi.lookup("8.8.8.8")
    assert g is not None
    assert g.asn == 15169
    assert g.country == "US"
    assert g.as_description == "GOOGLE"

    kr = gi.lookup("211.45.0.5")
    assert kr is not None and kr.asn == 9318 and kr.country == "KR"


def test_range_boundaries() -> None:
    gi = IpAsnLookup.from_iptoasn_tsv(V4)
    assert gi.lookup("1.0.0.0") is not None  # 시작 경계
    assert gi.lookup("1.0.0.255") is not None  # 끝 경계
    assert gi.lookup("1.0.1.0") is None  # 구간 밖(미등록)


def test_private_and_unrouted_return_none() -> None:
    gi = IpAsnLookup.from_iptoasn_tsv(V4)
    assert gi.lookup("10.1.2.3") is None  # 사설(is_global=False)
    assert gi.lookup("192.168.45.10") is None
    assert gi.lookup("not-an-ip") is None


def test_ipv6_separated_from_ipv4() -> None:
    gi = IpAsnLookup.from_iptoasn_tsv(V4, V6)
    g6 = gi.lookup("2001:4860:4860::8888")
    assert g6 is not None and g6.asn == 15169
    # v6 구간의 정수값이 v4 공간과 겹쳐도 교차 매칭되지 않아야 한다.
    assert gi.lookup("9.9.9.9") is None


def test_empty_lookup_without_db() -> None:
    gi = IpAsnLookup.empty()
    assert gi.lookup("8.8.8.8") is None  # DB 없으면 조용히 None
