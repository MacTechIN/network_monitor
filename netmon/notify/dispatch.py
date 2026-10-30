"""알림 디스패처: 우선순위 필터 → 조용한 시간 → 중복 억제 → 채널 발송.

실시간 탐지 경로와 분리된 발송 계층이다(계획서 §2 데이터흐름). dedup/조용한 시간은
Apprise 가 제공하지 않아 자체 구현한다(tech_research: Apprise 행). P2.5 의 새 기기
``is_new`` 트리거와 고심각도 알림이 여기로 들어온다.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from netmon.notify.channels import Channel

__all__ = [
    "Decision",
    "Dispatcher",
    "Notification",
    "QuietHours",
    "notification_for_new_device",
]


class Decision(StrEnum):
    SENT = "sent"
    DROPPED_PRIORITY = "dropped_priority"
    DROPPED_QUIET = "dropped_quiet"
    DROPPED_DEDUP = "dropped_dedup"


@dataclass(frozen=True, slots=True)
class Notification:
    """발송 후보 알림. ``priority`` 0=정보 1=낮음 2=높음 3=긴급."""

    kind: str
    title: str
    body: str
    dedup_key: str
    priority: int = 1
    ts: datetime | None = None


@dataclass(frozen=True, slots=True)
class QuietHours:
    """조용한 시간(로컬 시각 시간대). start>end 이면 자정을 넘는 구간(예: 23→7)."""

    start_hour: int
    end_hour: int

    def is_quiet(self, dt: datetime) -> bool:
        h = dt.hour
        if self.start_hour == self.end_hour:
            return False
        if self.start_hour < self.end_hour:
            return self.start_hour <= h < self.end_hour
        return h >= self.start_hour or h < self.end_hour


class Dispatcher:
    """알림을 필터링해 채널로 보낸다. 상태(중복 억제 캐시)를 보유한다."""

    def __init__(
        self,
        channels: Sequence[Channel],
        dedup_window: timedelta = timedelta(hours=1),
        min_priority: int = 1,
        quiet_hours: QuietHours | None = None,
        quiet_bypass_priority: int = 3,
    ) -> None:
        self._channels = list(channels)
        self._dedup_window = dedup_window
        self._min_priority = min_priority
        self._quiet = quiet_hours
        self._quiet_bypass = quiet_bypass_priority
        self._seen: dict[str, datetime] = {}

    def dispatch(self, notif: Notification, now: datetime | None = None) -> Decision:
        now = now or datetime.now(UTC)

        if notif.priority < self._min_priority:
            return Decision.DROPPED_PRIORITY

        if (
            self._quiet is not None
            and self._quiet.is_quiet(now)
            and notif.priority < self._quiet_bypass
        ):
            return Decision.DROPPED_QUIET

        last = self._seen.get(notif.dedup_key)
        if last is not None and now - last < self._dedup_window:
            return Decision.DROPPED_DEDUP

        for channel in self._channels:
            channel.send(notif)
        self._seen[notif.dedup_key] = now
        return Decision.SENT


def notification_for_new_device(
    key: str,
    label: str | None,
    ip: str | None = None,
    vendor: str | None = None,
) -> Notification:
    """P2.5 새 기기 탐지(``is_new``)를 알림으로 변환한다(FR-8)."""
    name = label or key
    parts = [p for p in (vendor, ip) if p]
    detail = f" ({', '.join(parts)})" if parts else ""
    return Notification(
        kind="new_device",
        title="새 기기 발견",
        body=f"{name}{detail} 가 네트워크에 처음 나타났습니다.",
        dedup_key=f"new_device:{key}",
        priority=2,
    )
