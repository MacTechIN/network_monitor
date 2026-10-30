"""알림 채널: 전송 대상 추상화와 Telegram 구현.

Telegram 은 Bot API 를 httpx 로 직접 호출한다. python-telegram-bot(GPL-3.0)은 쓰지 않는다
(CC2, tech_research §6.4). 다채널(Apprise, 이메일 등)은 같은 ``Channel`` 프로토콜로 추후 추가.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import httpx

    from netmon.notify.dispatch import Notification

__all__ = ["Channel", "TelegramChannel"]


class Channel(Protocol):
    """알림 하나를 전송한다. 실패는 예외로 전파한다(디스패처가 로깅/판단)."""

    def send(self, notif: Notification) -> None: ...


class TelegramChannel:
    """Telegram Bot API(`sendMessage`) 직접 호출 채널.

    네트워크 격리 테스트를 위해 httpx 클라이언트를 주입할 수 있다(MockTransport).
    """

    def __init__(self, bot_token: str, chat_id: str, client: httpx.Client | None = None) -> None:
        import httpx

        self._url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self._chat_id = chat_id
        self._client = client or httpx.Client(timeout=10.0)

    def send(self, notif: Notification) -> None:
        text = f"[{notif.priority}] {notif.title}\n{notif.body}"
        resp = self._client.post(self._url, json={"chat_id": self._chat_id, "text": text})
        resp.raise_for_status()
