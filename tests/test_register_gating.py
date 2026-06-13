"""Registration field gating: privileged fields are inert; non-privileged pass."""

from __future__ import annotations

import logging

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from crudauth import CookieConfig, CRUDAuth, SessionTransport
from crudauth.repository import (
    REGISTRATION_ALLOWED_FIELDS,
    REGISTRATION_GATED_FIELDS,
    UserRepository,
)


# A schema a careless dev might copy-paste from their UserCreate, leaking privilege.
class DangerousRegister(BaseModel):
    email: str
    username: str
    password: str
    full_name: str | None = None
    is_superuser: bool = False
    email_verified: bool = False


def test_allowlist_and_gated_sets_are_consistent() -> None:
    assert REGISTRATION_ALLOWED_FIELDS == {"email", "username"}
    # the gated set is everything privileged/state/identity - never user-settable
    assert {"is_superuser", "is_active", "email_verified", "hashed_password", "id"} <= (
        REGISTRATION_GATED_FIELDS
    )
    assert {"google_id", "github_id", "oauth_provider"} <= REGISTRATION_GATED_FIELDS
    # and the allowed fields are NOT in the gated set
    assert REGISTRATION_ALLOWED_FIELDS.isdisjoint(REGISTRATION_GATED_FIELDS)


def test_filter_drops_privileged_keeps_passthrough(UserModel) -> None:
    repo = UserRepository(UserModel)
    out = repo.filter_registration_data(
        {
            "email": "a@x.com",
            "username": "a",
            "full_name": "A",  # non-logical passthrough
            "is_superuser": True,  # gated
            "email_verified": True,  # gated
            "hashed_password": "x",  # gated
            "id": 99,  # gated
        }
    )
    assert out == {"email": "a@x.com", "username": "a", "full_name": "A"}


@pytest.fixture
async def client(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="x",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        register_schema=DangerousRegister,
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, auth
    await auth.shutdown()


async def test_privilege_escalation_is_inert(client, sessionmaker, UserModel) -> None:
    c, auth = client
    r = await c.post(
        "/register",
        json={
            "email": "evil@x.com",
            "username": "evil",
            "password": "pw123456",
            "full_name": "Evil",
            "is_superuser": True,
            "email_verified": True,
        },
    )
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "evil@x.com")
    assert user is not None
    # privileged fields were dropped; passthrough kept
    assert user.is_superuser is False
    assert user.email_verified is False
    assert user.full_name == "Evil"


def test_warns_at_startup_when_schema_declares_gated_field(get_session, UserModel, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="x",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            register_schema=DangerousRegister,
        )
    msg = caplog.text
    assert "privileged field" in msg
    assert "is_superuser" in msg
    assert "email_verified" in msg


def test_no_warning_for_clean_schema(get_session, UserModel, caplog) -> None:
    class CleanRegister(BaseModel):
        email: str
        username: str
        password: str
        full_name: str | None = None

    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="x",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            register_schema=CleanRegister,
        )
    assert "privileged field" not in caplog.text
