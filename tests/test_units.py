"""Unit tests for primitives: tokens, password hashing, OAuth linking, column_map."""

from __future__ import annotations

from datetime import timedelta


from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository
from crudauth.transports.bearer.tokens import (
    TokenType,
    create_access_token,
    create_signed_token,
    verify_signed_token,
    verify_token,
)
from crudauth.utils import (
    canonical_email,
    get_password_hash,
    make_unusable_password,
    verify_password,
)

SECRET = "unit-secret"


# --- password hashing --------------------------------------------------------
def test_password_roundtrip() -> None:
    h = get_password_hash("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)


def test_verify_password_handles_malformed_hash() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False


def test_unusable_password_never_verifies() -> None:
    sentinel = make_unusable_password()
    assert not verify_password("", sentinel)
    assert not verify_password("password", sentinel)


def test_canonical_email() -> None:
    assert canonical_email("  Foo@X.com ") == "foo@x.com"
    assert canonical_email(None) is None


# --- jwt tokens --------------------------------------------------------------
def test_access_token_roundtrip() -> None:
    token = create_access_token({"sub": "42"}, SECRET, scopes=["a", "b"])
    payload = verify_token(token, SECRET, TokenType.ACCESS)
    assert payload is not None
    assert payload["sub"] == "42"
    assert payload["scopes"] == ["a", "b"]


def test_access_token_wrong_type_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET)
    assert verify_token(token, SECRET, TokenType.REFRESH) is None


def test_token_wrong_secret_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET)
    assert verify_token(token, "other-secret", TokenType.ACCESS) is None


def test_expired_token_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET, expires_delta=timedelta(seconds=-1))
    assert verify_token(token, SECRET, TokenType.ACCESS) is None


def test_signed_token_purpose() -> None:
    token = create_signed_token(SECRET, 7, "verify_email")
    assert verify_signed_token(token, SECRET, "verify_email") == "7"
    assert verify_signed_token(token, SECRET, "reset_password") is None


# --- oauth account linking ---------------------------------------------------
async def test_oauth_creates_then_links(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)

    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="Person@Example.com",
        email_verified=True,
        name="A Person",
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is True
        assert repo.get(user, "email") == "person@example.com"
        assert repo.get(user, "google_id") == "g-1"

    # second time → same account, not created
    async with sessionmaker() as db:
        user2, created2 = await service.get_or_create_user(info, db)
        assert created2 is False
        assert repo.user_id(user2) == repo.user_id(user)


async def test_oauth_links_existing_email(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    # pre-existing password user
    async with sessionmaker() as db:
        existing = await repo.create(
            db,
            {
                "email": "dup@x.com",
                "username": "dup",
                "hashed_password": get_password_hash("pw"),
            },
        )
        existing_id = repo.user_id(existing)

    info = OAuthUserInfo(
        provider="github", provider_user_id="gh-9", email="dup@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is False
        assert repo.user_id(user) == existing_id
        assert repo.get(user, "github_id") == "gh-9"


# --- column_map --------------------------------------------------------------
def test_column_map_translation(UserModel) -> None:
    repo = UserRepository(UserModel, column_map={"email": "email", "id": "id"})
    assert repo.col("email") == "email"
    repo2 = UserRepository(UserModel, column_map={"hashed_password": "email"})
    assert repo2.col("hashed_password") == "email"
