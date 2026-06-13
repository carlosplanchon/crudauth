"""Built-in OAuth providers (Google, GitHub), registered on import."""

from __future__ import annotations

from ..constants import GITHUB, GOOGLE
from ..factory import OAuthProviderFactory
from .github import GitHubOAuthProvider
from .google import GoogleOAuthProvider

OAuthProviderFactory.register_provider(GOOGLE, GoogleOAuthProvider)
OAuthProviderFactory.register_provider(GITHUB, GitHubOAuthProvider)

__all__ = ["GoogleOAuthProvider", "GitHubOAuthProvider"]
