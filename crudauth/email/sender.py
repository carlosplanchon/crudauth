"""The delivery port. Implement [EmailSender.send][crudauth.email.sender.EmailSender.send] for your transport."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

__all__ = ["EmailSender", "EmailKind", "EMAIL_KINDS"]

# The message kinds crudauth asks the adapter to deliver. existing_account is a
# security notice ("someone tried to register with your email"), distinct from
# the cheery welcome.
EmailKind = Literal[
    "verify_email",
    "reset_password",
    "change_email",
    "welcome",
    "existing_account",
]

EMAIL_KINDS: tuple[EmailKind, ...] = (
    "verify_email",
    "reset_password",
    "change_email",
    "welcome",
    "existing_account",
)


class EmailSender(ABC):
    """Adapter crudauth calls to deliver a message.

    crudauth builds the subject and body (including the signed-token link) and
    hands them to you; you decide how to deliver (SMTP, SES, a task queue...).
    ``kind`` lets you pick the template; a bad ``kind`` is a type error.

    Example:
        ```python
        class MyEmailSender(EmailSender):
            async def send(self, *, to, subject, body, kind):
                await my_task_queue.enqueue(send_email, to=to, subject=subject, html=body)
        ```
    """

    @abstractmethod
    async def send(self, *, to: str, subject: str, body: str, kind: EmailKind) -> None:
        """Deliver one message.

        Args:
            to: Recipient address.
            subject: Message subject crudauth composed.
            body: Message body, including any signed-token link.
            kind: Which message this is - one of :data:`EMAIL_KINDS`. Use it to
                select the template (``existing_account`` is a security notice,
                not a welcome).
        """
        raise NotImplementedError
