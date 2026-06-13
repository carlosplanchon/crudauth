"""Cross-cutting helpers: password hashing, email normalization, request IP."""

from __future__ import annotations

import secrets
from typing import overload

import bcrypt
from fastapi import Request

__all__ = [
    "get_password_hash",
    "verify_password",
    "make_unusable_password",
    "canonical_email",
    "get_client_ip",
]


def get_password_hash(password: str) -> str:
    """Hash a plaintext password with bcrypt (random salt per call).

    Note: bcrypt only considers the first 72 bytes of the input; anything beyond
    that is silently ignored. If you enforce very long passwords, pre-hash (e.g.
    SHA-256) before calling, or cap length at the API layer.
    """
    hashed: bytes = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    Returns ``False`` (rather than raising) when the stored hash is malformed,
    so a corrupted row produces a clean "invalid password" path instead of a
    500 - which would both leak information and be a DoS lever.
    """
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except (ValueError, TypeError):
        return False


def make_unusable_password() -> str:
    """Return a sentinel that no input can ever verify against.

    Used for OAuth-only accounts. The leading ``!`` makes the value an invalid
    bcrypt hash, so [verify_password][crudauth.utils.verify_password] always returns ``False`` for it. The
    random suffix makes every sentinel unique. Mirrors Django's
    ``set_unusable_password``.
    """
    return "!" + secrets.token_urlsafe(16)


@overload
def canonical_email(email: str) -> str: ...
@overload
def canonical_email(email: None) -> None: ...
def canonical_email(email: str | None) -> str | None:
    """Normalize an email for storage/comparison (trim + lowercase).

    Ensures a user created via Google as ``Foo@x.com`` can log in by password as
    ``foo@x.com`` without surprises.
    """
    if email is None:
        return None
    return email.strip().lower()


def get_client_ip(request: Request) -> str:
    """Best-effort client IP, honoring ``X-Forwarded-For`` then ``X-Real-IP``."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client is not None:
        return request.client.host
    return "unknown"
