"""OUI(MAC 벤더) 매핑 — 로컬 IEEE 데이터만 사용 (외부 API 조회 금지, 정의서 §4).

arp-scan 이 설치하는 ``/usr/share/arp-scan/ieee-oui.txt``(``PREFIX<TAB>Vendor``)를 기본
데이터원으로 쓴다. MA-L(24bit)·MA-M(28bit)·MA-S(36bit) 블록을 긴 접두부터 조회한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["DEFAULT_OUI_PATH", "OUILookup"]

DEFAULT_OUI_PATH = Path("/usr/share/arp-scan/ieee-oui.txt")


def _mac_hex(mac: str) -> str:
    return mac.strip().upper().replace(":", "").replace("-", "")


@dataclass(frozen=True, slots=True)
class OUILookup:
    _map: dict[str, str]

    @classmethod
    def from_ieee_oui_txt(cls, path: Path | str) -> OUILookup:
        mapping: dict[str, str] = {}
        for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            prefix = _mac_hex(parts[0])
            vendor = parts[1].strip()
            if prefix and vendor:
                mapping[prefix] = vendor
        return cls(mapping)

    @classmethod
    def load_default(cls) -> OUILookup:
        """시스템 OUI 파일을 로드한다. 없으면 빈 조회기를 반환한다."""
        if DEFAULT_OUI_PATH.exists():
            return cls.from_ieee_oui_txt(DEFAULT_OUI_PATH)
        return cls({})

    def vendor(self, mac: str) -> str | None:
        h = _mac_hex(mac)
        for n in (9, 7, 6):  # MA-S(36bit), MA-M(28bit), MA-L(24bit)
            if len(h) >= n and h[:n] in self._map:
                return self._map[h[:n]]
        return None
