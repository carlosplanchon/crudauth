"""Email flows: the package mints/verifies signed tokens; you own delivery."""

from __future__ import annotations

from .config import EmailConfig
from .sender import EmailSender
from .service import EmailFlowService

__all__ = ["EmailSender", "EmailConfig", "EmailFlowService"]
