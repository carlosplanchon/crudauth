"""User model contract. Inherit [AuthUserMixin][crudauth.models.mixin.AuthUserMixin] for the happy path."""

from __future__ import annotations

from .mixin import AuthUserMixin

__all__ = ["AuthUserMixin"]
