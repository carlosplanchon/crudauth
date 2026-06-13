"""User-agent parsing - uses the optional ``user-agents`` package when present."""

from __future__ import annotations

from .schemas import UserAgentInfo

__all__ = ["parse_user_agent"]

try:
    from user_agents import parse as _ua_parse  # type: ignore

    _HAS_UA = True
except ImportError:  # pragma: no cover
    _HAS_UA = False


def parse_user_agent(user_agent_string: str) -> UserAgentInfo:
    """Parse a UA string into structured device info. Degrades gracefully."""
    if not _HAS_UA or not user_agent_string:
        return UserAgentInfo(browser="Unknown", os="Unknown", device="Unknown")
    ua = _ua_parse(user_agent_string)
    return UserAgentInfo(
        browser=ua.browser.family,
        browser_version=ua.browser.version_string,
        os=ua.os.family,
        device=ua.device.family,
        is_mobile=ua.is_mobile,
        is_tablet=ua.is_tablet,
        is_pc=ua.is_pc,
    )
