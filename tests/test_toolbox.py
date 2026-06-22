"""The toolbox surface: the hardened primitives are reusable à la carte.

These prove a hand-written login over ``auth.authenticate_password`` and a
hand-minted token over ``auth.issue_tokens`` get the same hardening as the
built-in routes, that the wired services are reachable (``auth.emails`` /
``auth.oauth``), and that the building blocks are importable from the package root.
"""

from contextlib import asynccontextmanager
from typing import Annotated, Any

import httpx
import pytest
from fastapi import Depends, FastAPI, Request, Response
from pydantic import BaseModel

from crudauth import (
    BearerTransport,
    CookieConfig,
    CRUDAuth,
    DeliveryChannel,
    DeliveryIntent,
    EmailFlowService,
    Principal,
    SessionTransport,
)
from crudauth.transports.bearer.tokens import TokenType, verify_token


class _NullChannel(DeliveryChannel):
    async def deliver(self, intent: DeliveryIntent, db: Any) -> None:
        pass


SECRET = "test-secret-key-0123456789-0123456789"


class _Login(BaseModel):
    username: str
    password: str


def _build(get_session, UserModel, *, transports=None, **kw):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=transports
        or [SessionTransport(cookies=CookieConfig(secure=False)), BearerTransport()],
        **kw,
    )
    app = FastAPI()
    app.include_router(auth.router)

    # a hand-rolled login that reuses the hardened credential check + session manager
    @app.post("/my-login")
    async def my_login(
        body: _Login,
        request: Request,
        response: Response,
        db: Annotated[Any, Depends(get_session)],
    ):
        user = await auth.authenticate_password(db, body.username, body.password, request=request)
        sid, csrf = await auth.sessions.create_session(request, user_id=auth.repo.user_id(user))
        auth.sessions.set_session_cookies(response, sid, csrf)
        return {"csrf": csrf}

    if auth._bearer_transport is not None:

        @app.get("/bearer-only")
        async def bearer_only(
            user: Annotated[Principal, Depends(auth.current_user(transport="bearer"))],
        ):
            return {"id": user.user_id, "scopes": user.scopes}

    return app, auth


@asynccontextmanager
async def _client(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


async def _register(c, **over):
    body = {"email": "a@x.com", "username": "alice", "password": "pw123456"}
    body.update(over)
    return await c.post("/register", json=body)


async def test_authenticate_password_powers_a_handrolled_login(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await _register(c)
        # the custom route authenticates and establishes a session
        r = await c.post("/my-login", json={"username": "alice", "password": "pw123456"})
        assert r.status_code == 200
        assert (await c.get("/me")).status_code == 200  # the session it set works
    await auth.shutdown()


async def test_authenticate_password_rejects_bad_credentials(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await _register(c)
        r = await c.post("/my-login", json={"username": "alice", "password": "nope"})
        assert r.status_code == 401  # UnauthorizedException maps through
    await auth.shutdown()


async def test_authenticate_password_carries_the_shared_lockout(get_session, UserModel) -> None:
    app, auth = _build(
        get_session,
        UserModel,
        transports=[SessionTransport(cookies=CookieConfig(secure=False), login_max_attempts=2)],
    )
    await auth.initialize()
    async with _client(app) as c:
        await _register(c)
        statuses = [
            (await c.post("/my-login", json={"username": "alice", "password": "x"})).status_code
            for _ in range(3)
        ]
        assert statuses[0] == 401
        assert 429 in statuses  # the hand-rolled login inherits the lockout
    await auth.shutdown()


async def test_issue_tokens_mints_a_usable_token(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await _register(c)
        async with _session(get_session) as db:
            user = await auth.repo.get_by_email(db, "a@x.com")
            tokens = auth.issue_tokens(user)
        assert "refresh_token" in tokens  # no Response -> refresh in the body
        r = await c.get(
            "/bearer-only", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert r.status_code == 200
    await auth.shutdown()


async def test_issue_tokens_clamps_scopes(get_session, UserModel) -> None:
    app, auth = _build(
        get_session,
        UserModel,
        transports=[BearerTransport(grantable_scopes=["read"])],
    )
    await auth.initialize()
    async with _client(app) as c:
        await _register(c)
        async with _session(get_session) as db:
            user = await auth.repo.get_by_email(db, "a@x.com")
            tokens = auth.issue_tokens(user, scopes=["read", "admin"])  # admin not grantable
        payload = verify_token(tokens["access_token"], SECRET, TokenType.ACCESS, algorithm="HS256")
        assert payload is not None
        assert payload.get("scopes") == ["read"]  # admin dropped by the clamp
    await auth.shutdown()


async def test_issue_tokens_without_bearer_raises(get_session, UserModel) -> None:
    app, auth = _build(
        get_session, UserModel, transports=[SessionTransport(cookies=CookieConfig(secure=False))]
    )
    await auth.initialize()
    with pytest.raises(RuntimeError):
        auth.issue_tokens(object())
    await auth.shutdown()


async def test_service_accessors(get_session, UserModel) -> None:
    # configured -> the wired service; unconfigured -> None
    _, with_email = _build(get_session, UserModel, channels=[_NullChannel()])
    assert isinstance(with_email.emails, EmailFlowService)

    _, plain = _build(get_session, UserModel)
    assert plain.emails is None
    assert plain.oauth is None


# --- helpers ---------------------------------------------------------------


@asynccontextmanager
async def _session(get_session):
    gen = get_session()
    db = await gen.__anext__()
    try:
        yield db
    finally:
        await gen.aclose()
