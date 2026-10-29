"""OUI 매핑: 로컬 IEEE 파일 로드와 MA-L/MA-S 접두 조회를 검증한다."""

from __future__ import annotations

from pathlib import Path

from netmon.enrich.oui import DEFAULT_OUI_PATH, OUILookup

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ieee-oui-sample.txt"


def test_vendor_lookup_ma_l() -> None:
    oui = OUILookup.from_ieee_oui_txt(FIXTURE)
    assert oui.vendor("b8:27:eb:11:22:33") == "Raspberry Pi Foundation"
    assert oui.vendor("3C:22:FB:00:11:22") == "Apple, Inc."


def test_vendor_lookup_ma_s_prefers_longer_prefix() -> None:
    oui = OUILookup.from_ieee_oui_txt(FIXTURE)
    assert oui.vendor("8c:1f:64:fa:0b:cc") == "MA-S Example Vendor"


def test_unknown_returns_none() -> None:
    oui = OUILookup.from_ieee_oui_txt(FIXTURE)
    assert oui.vendor("de:ad:be:ef:00:01") is None


def test_load_default_is_safe_when_absent() -> None:
    oui = OUILookup.load_default()
    assert isinstance(oui, OUILookup)
    # 시스템 파일이 있으면 Raspberry Pi 접두가 해석되어야 한다.
    if DEFAULT_OUI_PATH.exists():
        assert oui.vendor("b8:27:eb:00:00:00") is not None
