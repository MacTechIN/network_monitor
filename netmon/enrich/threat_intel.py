"""위협 인텔 매칭 — 로컬 피드만 사용 (내부 관측값 외부 전송 없음, 정의서 §4 / CC4).

키 없이 쓰는 기본 피드: abuse.ch Feodo·SSLBL(botnet C2 IP), Spamhaus DROP(CIDR).
misp-warninglists(알려진 정상 IP/CIDR: 공개 DNS, 클라우드, bogon 등)는 오탐 억제용 허용목록.
URLhaus·ThreatFox 는 ``abusech_auth_key`` 입력 시에만 opt-in 으로 얹는다(여기선 파일 로더만 제공).

피드 파일은 운영 중 배치로 내려받아 로컬에 둔다. 조회(``match``)는 외부로 나가지 않는다.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ThreatIntel", "ThreatMatch"]

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class ThreatMatch:
    source: str
    category: str | None
    reference: str | None


def _first_ip(line: str) -> str | None:
    """한 줄에서 IP 로 파싱되는 첫 토큰을 찾는다(IP-우선 .txt·날짜-우선 CSV 모두 대응)."""
    for tok in line.replace(",", " ").split():
        try:
            return ipaddress.ip_address(tok.strip()).compressed
        except ValueError:
            continue
    return None


class ThreatIntel:
    def __init__(self) -> None:
        self._block_ips: dict[str, ThreatMatch] = {}
        self._block_cidrs: list[tuple[_IpNetwork, ThreatMatch]] = []
        self._allow_ips: set[str] = set()
        self._allow_cidrs: list[_IpNetwork] = []

    # --- 로더 ---------------------------------------------------------------
    def add_ip_blocklist(self, path: Path | str, source: str, category: str | None) -> None:
        for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key = _first_ip(line)
            if key is not None:
                self._block_ips.setdefault(key, ThreatMatch(source, category, None))

    def add_cidr_blocklist(self, path: Path | str, source: str, category: str | None) -> None:
        """Spamhaus DROP 형식(``CIDR ; SBLref``)과 단순 CIDR 목록 모두 지원."""
        for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith((";", "#")):
                continue
            cidr, _, rest = line.partition(";")
            ref = rest.strip() or None
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
            except ValueError:
                continue
            self._block_cidrs.append((net, ThreatMatch(source, category, ref)))

    def add_warninglist_values(self, values: list[str]) -> None:
        for v in values:
            tok = v.strip()
            if not tok:
                continue
            try:
                if "/" in tok:
                    self._allow_cidrs.append(ipaddress.ip_network(tok, strict=False))
                else:
                    self._allow_ips.add(ipaddress.ip_address(tok).compressed)
            except ValueError:
                continue

    def add_warninglist_json(self, path: Path | str) -> None:
        """misp-warninglists 항목(JSON ``{"list": [...]}``)을 허용목록에 추가한다."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        values = data.get("list") if isinstance(data, dict) else None
        if isinstance(values, list):
            self.add_warninglist_values([str(v) for v in values])

    # --- 조회 ---------------------------------------------------------------
    def is_allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        if addr.compressed in self._allow_ips:
            return True
        return any(addr in net for net in self._allow_cidrs)

    def match(self, ip: str) -> ThreatMatch | None:
        """위협 피드에 걸리면 매치를 돌려준다. 허용목록·사설·미등록은 None(오탐 억제)."""
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        if not addr.is_global:
            return None
        if self.is_allowlisted(ip):  # 알려진 정상 → 오탐 억제
            return None
        hit = self._block_ips.get(addr.compressed)
        if hit is not None:
            return hit
        for net, m in self._block_cidrs:
            if addr in net:
                return m
        return None
