"""P3.4 알림 디스패처: 우선순위·조용한 시간·중복 억제와 Telegram 채널(격리) 검증."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from netmon.notify.channels import TelegramChannel
from netmon.notify.dispatch import (
    Decision,
    Dispatcher,
    Notification,
    QuietHours,
    notification_for_new_device,
)


class _RecordingChannel:
    def __init__(self) -> None:
        self.sent: list[Notification] = []

    def send(self, notif: Notification) -> None:
        self.sent.append(notif)


def _at(hour: int) -> datetime:
    return datetime(2026, 10, 30, hour, 0, tzinfo=UTC)


def _notif(priority: int = 2, key: str = "k") -> Notification:
    return Notification(kind="alert", title="t", body="b", dedup_key=key, priority=priority)


def test_quiet_hours_wraparound() -> None:
    q = QuietHours(start_hour=23, end_hour=7)
    assert q.is_quiet(_at(23)) is True
    assert q.is_quiet(_at(3)) is True
    assert q.is_quiet(_at(7)) is False
    assert q.is_quiet(_at(12)) is False


def test_quiet_hours_same_day_and_equal() -> None:
    assert QuietHours(9, 17).is_quiet(_at(12)) is True
    assert QuietHours(9, 17).is_quiet(_at(8)) is False
    assert QuietHours(5, 5).is_quiet(_at(5)) is False  # 빈 구간


def test_priority_filter() -> None:
    ch = _RecordingChannel()
    d = Dispatcher([ch], min_priority=2)
    assert d.dispatch(_notif(priority=1), now=_at(12)) is Decision.DROPPED_PRIORITY
    assert d.dispatch(_notif(priority=2), now=_at(12)) is Decision.SENT
    assert len(ch.sent) == 1


def test_quiet_suppress_and_bypass() -> None:
    ch = _RecordingChannel()
    d = Dispatcher([ch], quiet_hours=QuietHours(23, 7), quiet_bypass_priority=3)
    assert d.dispatch(_notif(priority=2, key="a"), now=_at(2)) is Decision.DROPPED_QUIET
    assert d.dispatch(_notif(priority=3, key="b"), now=_at(2)) is Decision.SENT  # 긴급 우회
    assert d.dispatch(_notif(priority=2, key="c"), now=_at(12)) is Decision.SENT  # 낮엔 통과


def test_dedup_window() -> None:
    ch = _RecordingChannel()
    d = Dispatcher([ch], dedup_window=timedelta(hours=1))
    base = _at(12)
    assert d.dispatch(_notif(key="x"), now=base) is Decision.SENT
    assert d.dispatch(_notif(key="x"), now=base + timedelta(minutes=30)) is Decision.DROPPED_DEDUP
    assert d.dispatch(_notif(key="x"), now=base + timedelta(hours=2)) is Decision.SENT
    assert d.dispatch(_notif(key="y"), now=base) is Decision.SENT  # 다른 키는 독립
    assert len(ch.sent) == 3


def test_notification_for_new_device() -> None:
    n = notification_for_new_device("mac:aa:bb", "거실TV", ip="192.168.45.40", vendor="Samsung")
    assert n.kind == "new_device"
    assert n.priority == 2
    assert n.dedup_key == "new_device:mac:aa:bb"
    assert "거실TV" in n.body and "Samsung" in n.body


def test_telegram_channel_posts_payload() -> None:
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ch = TelegramChannel("TOKEN", "12345", client=client)
    ch.send(_notif(priority=3))

    assert len(captured) == 1
    assert captured[0]["chat_id"] == "12345"
    text = captured[0]["text"]
    assert isinstance(text, str) and text.startswith("[3] t")


def test_telegram_channel_raises_on_error() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(500)))
    ch = TelegramChannel("TOKEN", "12345", client=client)
    with pytest.raises(httpx.HTTPStatusError):
        ch.send(_notif())
