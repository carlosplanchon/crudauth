"""The [Principal][crudauth.principal.Principal] - the single identity object every transport returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["Principal"]


@dataclass(frozen=True)
class Principal:
    """An authenticated identity, independent of which transport authenticated it.

    Every transport (session, bearer, api key, ...) returns the *same* shape,
    keyed by ``user_id``. Narrowing transports never changes the identity model.

    Attributes:
        user_id: Immutable identity handle (the user's primary key).
        scopes: Flat capability scopes carried by this credential. Session
            principals carry empty scopes in v1; bearer/api-key principals carry
            whatever was issued.
        transport: Name of the transport that authenticated this request
            (``"session"``, ``"bearer"``, ...).
        user: The resolved user row (your ``User`` ORM instance), or ``None`` if
            a transport chose not to resolve it.
        is_superuser: Whether the user holds the superuser flag.
        email_verified: Whether the user's email is verified.

    Example:
        ```python
        @app.get("/whoami")
        async def whoami(user: Principal = Depends(auth.current_user())):
            return {"id": user.user_id, "via": user.transport, "email": user.user.email}
        ```
    """

    user_id: Any
    scopes: tuple[str, ...] = ()
    transport: str = ""
    user: Any = None
    is_superuser: bool = False
    email_verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_scopes(self, required: list[str] | tuple[str, ...]) -> bool:
        """True if this principal's scopes are a superset of ``required``."""
        return set(required).issubset(set(self.scopes))
