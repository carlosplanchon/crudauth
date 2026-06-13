"""The bearer transport: ``Authorization: Bearer <jwt>`` for apps and scripts."""

from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ...constants import (
    DEFAULT_ACCESS_TTL_SECONDS,
    DEFAULT_REFRESH_TTL_DAYS,
    SECONDS_PER_DAY,
)
from ...core import AuthContext, AuthRuntime, CookieConfig, Transport
from ...exceptions import RateLimitException, UnauthorizedException
from ...hooks import HookContext
from ...principal import Principal
from ...utils import (
    canonical_identifier,
    dummy_verify_password,
    get_client_ip,
    verify_password,
)
from .constants import (
    REFRESH_LOCATION_BODY,
    REFRESH_LOCATION_COOKIE,
    REFRESH_LOCATIONS,
    REFRESH_TOKEN_NAME,
    TOKEN_TYPE_BEARER,
)
from .tokens import (
    TokenType,
    create_access_token,
    create_refresh_token,
    verify_token,
)

__all__ = ["BearerTransport"]


class BearerTransport(Transport):
    """Stateless JWT auth.

    Args:
        access_ttl: Access token lifetime in seconds (default 15 min).
        refresh_ttl_days: Refresh token lifetime in days (default 30).
        refresh: Where the refresh token lives - ``"cookie"`` (httpOnly, default)
            or ``"body"`` (returned in the JSON response).
        default_scopes: Scopes granted to password-login tokens when the client
            doesn't request a narrower set.

    Note:
        Bearer tokens are **stateless** - there is no server-side revocation or
        rotation, so a stolen refresh token is valid until it expires
        (``refresh_ttl_days``, default 30). For revocable, "sign out everywhere"
        auth, use the session transport (``auth.sessions.revoke*``). Refresh-token
        rotation is a planned future addition.

    Note:
        ``/token`` shares the escalating login lockout with the session
        ``/login`` route (same ``runtime.lockout``, keyed by ip + username), so a
        client locked out on one endpoint can't brute-force via the other.

    Example:
        ```python
        BearerTransport(access_ttl=900, refresh="cookie")
        ```
    """

    name = "bearer"

    def __init__(
        self,
        *,
        access_ttl: int = DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl_days: int = DEFAULT_REFRESH_TTL_DAYS,
        refresh: str = REFRESH_LOCATION_COOKIE,
        default_scopes: list[str] | None = None,
        refresh_cookie_name: str = REFRESH_TOKEN_NAME,
        cookies: CookieConfig | None = None,
    ):
        if refresh not in REFRESH_LOCATIONS:
            raise ValueError("refresh must be 'cookie' or 'body'")
        self.access_ttl = access_ttl
        self.refresh_ttl_days = refresh_ttl_days
        self.refresh = refresh
        self.default_scopes = tuple(default_scopes or ())
        self.refresh_cookie_name = refresh_cookie_name
        self._cookie_override = cookies

    # --- authn ---------------------------------------------------------------
    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        """Authenticate an ``Authorization: Bearer`` access token.

        Note:
            Absent or non-bearer header → ``None`` (this transport's credential
            isn't present; the facade tries the next transport). A present but
            *invalid* token (bad signature, expired, wrong type) → raises
            ``UnauthorizedException`` (Convention 6: a tampered credential
            hard-fails rather than silently falling through), mirroring the
            session transport's CSRF behavior. A valid token whose user no longer
            exists / is inactive returns ``None`` (account vanished, treat as
            anonymous), matching the session transport.
        """
        header = request.headers.get("authorization")
        if not header:
            return None
        scheme, _, token = header.partition(" ")
        if scheme.lower() != TOKEN_TYPE_BEARER or not token:
            return None

        payload = verify_token(
            token, self.runtime.secret_key, TokenType.ACCESS, algorithm=self.runtime.algorithm
        )
        if payload is None:
            raise UnauthorizedException("Invalid or expired token")

        user = await ctx.resolve_user(payload["sub"])
        if user is None or not ctx.repo.is_active(user):
            return None

        scopes = tuple(payload.get("scopes") or ())
        return ctx.build_principal(
            user_id=ctx.repo.user_id(user), user=user, transport=self.name, scopes=scopes
        )

    # --- routes --------------------------------------------------------------
    def contributes_routes(self) -> APIRouter:
        router = APIRouter(tags=["auth"])
        runtime = self.runtime
        db_dep = runtime.db_dependency

        @router.post("/token")
        async def issue_token(
            request: Request,
            response: Response,
            form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
            db: Annotated[Any, Depends(db_dep)],
        ):
            """Exchange username/email + password for an access token.

            Returns ``{"access_token", "token_type"}``; the refresh token is set
            as an httpOnly cookie or returned in the body per ``refresh=``.
            Subject to the shared login lockout.
            """
            ip = get_client_ip(request, runtime.trusted_proxy_hops)
            login_id = canonical_identifier(form_data.username)
            lockout = runtime.lockout
            if lockout is not None:
                allowed, _, retry_after = await lockout.check_and_record(
                    ip, login_id, success=False
                )
                if not allowed:
                    raise RateLimitException(
                        "Too many login attempts. Try again later.", retry_after=retry_after
                    )

            user = await runtime.repo.get_by_identifier(db, form_data.username)
            if user is None:
                dummy_verify_password(form_data.password)
                raise UnauthorizedException("Incorrect username or password")
            if not verify_password(
                form_data.password, runtime.repo.get(user, "hashed_password", "")
            ):
                raise UnauthorizedException("Incorrect username or password")
            if not runtime.repo.is_active(user):
                raise UnauthorizedException("Account is disabled")

            if lockout is not None:
                await lockout.check_and_record(ip, login_id, success=True)

            scopes = tuple(form_data.scopes) if form_data.scopes else self.default_scopes
            body = self._mint(runtime, user, scopes, response)
            await runtime.hooks.run_after_login(
                runtime.repo.to_dict(user),
                request=request,
                context=HookContext(
                    ip_address=ip,
                    user_agent=request.headers.get("user-agent"),
                    transport=self.name,
                    request=request,
                ),
            )
            return body

        @router.post("/refresh")
        async def refresh_token(request: Request, db: Annotated[Any, Depends(db_dep)]):
            """Mint a fresh access token from a valid refresh token (cookie or body)."""
            token = await self._read_refresh(request)
            if not token:
                raise UnauthorizedException("Refresh token missing")
            payload = verify_token(
                token, runtime.secret_key, TokenType.REFRESH, algorithm=runtime.algorithm
            )
            if payload is None:
                raise UnauthorizedException("Invalid or expired refresh token")
            user = await runtime.repo.get_by_id(db, payload["sub"])
            if user is None or not runtime.repo.is_active(user):
                raise UnauthorizedException("Invalid or expired refresh token")
            scopes = tuple(payload.get("scopes") or ())
            access = create_access_token(
                {"sub": str(runtime.repo.user_id(user))},
                runtime.secret_key,
                expires_delta=timedelta(seconds=self.access_ttl),
                algorithm=runtime.algorithm,
                scopes=list(scopes),
            )
            return {"access_token": access, "token_type": TOKEN_TYPE_BEARER}

        return router

    # --- helpers -------------------------------------------------------------
    def _mint(
        self, runtime: AuthRuntime, user: Any, scopes: tuple[str, ...], response: Response
    ) -> dict[str, Any]:
        uid = str(runtime.repo.user_id(user))
        access = create_access_token(
            {"sub": uid},
            runtime.secret_key,
            expires_delta=timedelta(seconds=self.access_ttl),
            algorithm=runtime.algorithm,
            scopes=list(scopes),
        )
        refresh = create_refresh_token(
            {"sub": uid, "scopes": list(scopes)},
            runtime.secret_key,
            expires_delta=timedelta(days=self.refresh_ttl_days),
            algorithm=runtime.algorithm,
        )
        body = {"access_token": access, "token_type": TOKEN_TYPE_BEARER}
        if self.refresh == REFRESH_LOCATION_COOKIE and response is not None:
            cookies = self.cookie_config()
            response.set_cookie(
                key=self.refresh_cookie_name,
                value=refresh,
                httponly=True,
                secure=cookies.secure,
                samesite=cookies.samesite,
                max_age=self.refresh_ttl_days * SECONDS_PER_DAY,
                path=cookies.path,
            )
        else:
            body[REFRESH_TOKEN_NAME] = refresh
        return body

    async def _read_refresh(self, request: Request) -> str | None:
        cookie = request.cookies.get(self.refresh_cookie_name)
        if cookie:
            return cookie
        if self.refresh == REFRESH_LOCATION_BODY:
            try:
                body = await request.json()
            except Exception:
                return None
            if isinstance(body, dict):
                return body.get(REFRESH_TOKEN_NAME)
        return None
