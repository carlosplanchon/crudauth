"""User persistence, decoupled from your concrete model via ``column_map``.

crudauth speaks a small *logical contract* of field names (``id``, ``email``,
``hashed_password``, ...). [UserRepository][crudauth.repository.UserRepository] translates that contract to
the actual attribute names on your model, so you never have to rename your
schema to adopt the library.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .utils import canonical_email

__all__ = ["UserRepository", "LOGICAL_FIELDS", "REGISTRATION_ALLOWED_FIELDS"]

# Sentinel: a value that could not be coerced to the PK type (so no row matches).
_UNCOERCIBLE = object()

# Logical field names crudauth understands.
LOGICAL_FIELDS = (
    "id",
    "email",
    "username",
    "hashed_password",
    "is_active",
    "is_superuser",
    "email_verified",
    "oauth_provider",
    "google_id",
    "github_id",
    "oauth_created_at",
    "oauth_updated_at",
)

# The ONLY logical fields a user may set during self-registration. Everything
# else in LOGICAL_FIELDS is privilege/state/identity-linkage (is_superuser,
# is_active, email_verified, hashed_password, the oauth linkage, the PK) and is
# dropped at the registration path. This is an *allowlist* on purpose: adding a
# new sensitive column to your model later fails safe (not settable at signup)
# rather than fails open. ``password`` is plaintext input, not a logical column,
# so it isn't here - it's hashed into ``hashed_password`` by the route.
REGISTRATION_ALLOWED_FIELDS = frozenset({"email", "username"})

# Logical fields that registration must never accept (the gated set).
REGISTRATION_GATED_FIELDS = frozenset(LOGICAL_FIELDS) - REGISTRATION_ALLOWED_FIELDS


class UserRepository:
    def __init__(self, model: type[Any], column_map: dict[str, str] | None = None):
        self.model = model
        self.column_map = column_map or {}

    # --- contract translation ------------------------------------------------
    def col(self, logical: str) -> str:
        """Resolve a logical field name to the actual model attribute name."""
        return self.column_map.get(logical, logical)

    def has(self, logical: str) -> bool:
        return hasattr(self.model, self.col(logical))

    def get(self, user: Any, logical: str, default: Any = None) -> Any:
        return getattr(user, self.col(logical), default)

    def set_field(self, user: Any, logical: str, value: Any) -> None:
        setattr(user, self.col(logical), value)

    def _attr(self, logical: str) -> Any:
        return getattr(self.model, self.col(logical))

    # --- reads ---------------------------------------------------------------
    def _coerce_id(self, user_id: Any) -> Any:
        """Coerce ``user_id`` to the PK's Python type.

        JWT subjects round-trip as strings (``"42"``); the session path carries
        native ints. Coercing here means *both* paths hit the DB with the right
        type - SQLite tolerates ``"42" == 42`` but Postgres/asyncpg does not.
        Returns ``_UNCOERCIBLE`` when conversion is impossible (e.g. ``"abc"``
        against an int PK), so the lookup can short-circuit to ``None``.
        """
        try:
            py_type = self._attr("id").type.python_type
        except (AttributeError, NotImplementedError):
            return user_id
        if isinstance(user_id, py_type):
            return user_id
        try:
            return py_type(user_id)
        except (ValueError, TypeError):
            return _UNCOERCIBLE

    async def get_by_id(self, db: AsyncSession, user_id: Any) -> Any | None:
        """Fetch the user by primary key, or ``None``.

        Args:
            db: Active async session.
            user_id: PK value; coerced to the column's Python type first (so a
                string ``"42"`` from a token matches an int PK on Postgres).

        Returns:
            The user row, or ``None`` if absent or ``user_id`` can't be coerced.
        """
        coerced = self._coerce_id(user_id)
        if coerced is _UNCOERCIBLE:
            return None
        result = await db.execute(select(self.model).where(self._attr("id") == coerced))
        return result.scalar_one_or_none()

    async def get_by_email(self, db: AsyncSession, email: str) -> Any | None:
        """Fetch the user by (canonicalized) email, or ``None``."""
        result = await db.execute(
            select(self.model).where(self._attr("email") == canonical_email(email))
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, db: AsyncSession, username: str) -> Any | None:
        """Fetch the user by username, or ``None``."""
        result = await db.execute(select(self.model).where(self._attr("username") == username))
        return result.scalar_one_or_none()

    async def get_by_identifier(self, db: AsyncSession, identifier: str) -> Any | None:
        """Look up by email when the identifier contains ``@``, else by username."""
        if "@" in identifier:
            return await self.get_by_email(db, identifier)
        return await self.get_by_username(db, identifier)

    async def get_by_oauth(
        self, db: AsyncSession, provider: str, provider_user_id: str
    ) -> Any | None:
        """Look up by ``{provider}_id``.

        Note:
            Assumes ``provider`` is a validated/registered provider name (the
            OAuth router checks it before this is reached) - it builds an
            attribute name from the argument, so an unvalidated value would
            probe arbitrary columns (it returns ``None`` for any column the
            model lacks, so the blast radius is a missed lookup, not a leak).
        """
        field = f"{provider}_id"
        if not self.has(field):
            return None
        result = await db.execute(select(self.model).where(self._attr(field) == provider_user_id))
        return result.scalar_one_or_none()

    async def username_exists(self, db: AsyncSession, username: str) -> bool:
        return (await self.get_by_username(db, username)) is not None

    # --- registration gating -------------------------------------------------
    def _gated_names(self) -> set[str]:
        """Gated identifiers: the logical names AND their mapped column names.

        Including the resolved column names closes the alias hole - a
        ``column_map`` that renames ``is_superuser`` to ``is_admin`` plus a
        register schema declaring ``is_admin`` would otherwise slip a gated
        field past a logical-only gate.
        """
        return set(REGISTRATION_GATED_FIELDS) | {self.col(g) for g in REGISTRATION_GATED_FIELDS}

    def gated_register_fields(self, schema_fields: Iterable[str]) -> set[str]:
        """Which of ``schema_fields`` registration will drop (logical or mapped name)."""
        gated = self._gated_names()
        return {f for f in schema_fields if f in gated}

    def filter_registration_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Strip privileged fields from a registration payload.

        A crudauth logical field is kept only if it's in
        :data:`REGISTRATION_ALLOWED_FIELDS`; gated fields (``is_superuser``,
        ``hashed_password``, oauth linkage, the PK, ...) are dropped silently -
        by both their logical name *and* their mapped column name. Non-logical
        fields (your own columns, e.g. ``full_name``) pass through untouched, so
        a custom ``register_schema`` can't turn ``/register`` into a
        privilege-escalation endpoint.
        """
        gated = self._gated_names()
        return {k: v for k, v in data.items() if k not in gated}

    # --- writes --------------------------------------------------------------
    async def create(self, db: AsyncSession, data: dict[str, Any]) -> Any:
        """Insert a user from logical-field ``data`` and return the row.

        Note:
            Owns the transaction boundary - commits and refreshes on the passed-in
            session. Apps using a request-scoped "commit at the end" pattern
            should know auth writes commit eagerly.

        Note:
            Email is canonicalized off the *resolved* column: ``kwargs`` is keyed
            by actual column names, so a ``column_map`` that renames ``email``
            would otherwise be stored un-normalized (Convention 5).
        """
        kwargs: dict[str, Any] = {}
        for logical, value in data.items():
            actual = self.col(logical)
            if hasattr(self.model, actual):
                kwargs[actual] = value
        email_col = self.col("email")
        if email_col in kwargs and isinstance(kwargs[email_col], str):
            kwargs[email_col] = canonical_email(kwargs[email_col])
        user = self.model(**kwargs)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    async def update(self, db: AsyncSession, user: Any, data: dict[str, Any]) -> Any:
        """Apply logical-field ``data`` to ``user`` and return it.

        Note:
            Commits and refreshes eagerly on the passed-in session (see
            [create][crudauth.repository.UserRepository.create]).
        """
        for logical, value in data.items():
            if logical == "email" and isinstance(value, str):
                value = canonical_email(value)
            if self.has(logical):
                self.set_field(user, logical, value)
        await db.commit()
        await db.refresh(user)
        return user

    # --- principal flags -----------------------------------------------------
    def is_superuser(self, user: Any) -> bool:
        return bool(self.get(user, "is_superuser", False))

    def email_verified(self, user: Any) -> bool:
        return bool(self.get(user, "email_verified", False))

    def is_active(self, user: Any) -> bool:
        if not self.has("is_active"):
            return True
        return bool(self.get(user, "is_active", True))

    def user_id(self, user: Any) -> Any:
        return self.get(user, "id")

    def to_dict(self, user: Any) -> dict[str, Any]:
        """Project a user row onto the logical contract (for hooks).

        Note:
            Contract-only by design - the dict holds the crudauth logical fields
            (``id``, ``email``, ...), not your app's own columns. A hook that
            needs ``full_name`` should re-load the row via ``db`` using the
            ``id``, not expect it in this dict.
        """
        return {f: self.get(user, f) for f in LOGICAL_FIELDS if self.has(f)}
