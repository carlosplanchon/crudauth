"""Google OAuth provider."""

from __future__ import annotations

from typing import Any

from ...exceptions import BadRequestException
from ..constants import (
    GOOGLE,
    GOOGLE_AUTHORIZE_ENDPOINT,
    GOOGLE_DEFAULT_SCOPES,
    GOOGLE_TOKEN_ENDPOINT,
    GOOGLE_USERINFO_ENDPOINT,
)
from ..provider import AbstractOAuthProvider
from ..schemas import OAuthUserInfo

__all__ = ["GoogleOAuthProvider"]


class GoogleOAuthProvider(AbstractOAuthProvider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes or list(GOOGLE_DEFAULT_SCOPES),
            authorize_endpoint=GOOGLE_AUTHORIZE_ENDPOINT,
            token_endpoint=GOOGLE_TOKEN_ENDPOINT,
            userinfo_endpoint=GOOGLE_USERINFO_ENDPOINT,
            provider_name=GOOGLE,
        )

    def get_authorization_url(self, state=None, pkce=True, extra_params=None):
        extra = {"access_type": "offline", "prompt": "consent"}
        if extra_params:
            extra.update(extra_params)
        return super().get_authorization_url(state=state, pkce=pkce, extra_params=extra)

    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        """Normalize Google's userinfo payload.

        Note:
            Raises if ``sub`` is missing rather than coercing ``None`` to the
            string ``"None"`` and storing it as a real ``provider_user_id``.
        """
        sub = user_info.get("sub")
        if sub is None:
            raise BadRequestException("Google did not return a user id (sub).")
        return OAuthUserInfo(
            provider=GOOGLE,
            provider_user_id=str(sub),
            email=user_info.get("email"),
            email_verified=bool(user_info.get("email_verified", False)),
            name=user_info.get("name"),
            given_name=user_info.get("given_name"),
            family_name=user_info.get("family_name"),
            username=None,
            picture=user_info.get("picture"),
            raw_data=user_info,
        )
