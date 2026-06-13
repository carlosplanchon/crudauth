"""Configuration for the email flows."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..constants import (
    DEFAULT_CHANGE_TTL_HOURS,
    DEFAULT_RESET_TTL_HOURS,
    DEFAULT_VERIFY_TTL_HOURS,
)
from .constants import DEFAULT_CHANGE_PATH, DEFAULT_RESET_PATH, DEFAULT_VERIFY_PATH
from .sender import EmailSender

__all__ = ["EmailConfig"]

logger = logging.getLogger("crudauth")


@dataclass
class EmailConfig:
    """Wire the sender port plus token lifetimes and link targets.

    Links point at ``frontend_url`` with the signed token appended as a query
    param, e.g. ``{frontend_url}{verify_path}?token=...``.

    Note:
        Putting the token in a URL query string is acceptable *only* because the
        tokens are one-time-use (consumed via a TTL'd store) and short-lived; a
        leaked link is single-shot and expires fast. ``frontend_url`` should be
        set - an empty value produces host-less, dead links and is warned about
        at construction.

    Example:
        ```python
        EmailConfig(sender=MyEmailSender(), frontend_url="https://app.example.com")
        ```
    """

    sender: EmailSender
    frontend_url: str = ""
    verify_ttl_hours: int = DEFAULT_VERIFY_TTL_HOURS
    reset_ttl_hours: int = DEFAULT_RESET_TTL_HOURS
    change_ttl_hours: int = DEFAULT_CHANGE_TTL_HOURS
    verify_path: str = DEFAULT_VERIFY_PATH
    reset_path: str = DEFAULT_RESET_PATH
    change_path: str = DEFAULT_CHANGE_PATH

    def __post_init__(self) -> None:
        if not self.frontend_url:
            logger.warning(
                "EmailConfig.frontend_url is empty; verification/reset links will be "
                "host-less and unclickable. Set it to your app's base URL."
            )

    def link(self, path: str, token: str) -> str:
        """Build a frontend link: ``{frontend_url}{path}?token={token}``."""
        base = self.frontend_url.rstrip("/")
        return f"{base}{path}?token={token}"
