"""Named constants for the package.

Consolidated here (rather than scattered per-subpackage) so every TTL, window,
and byte size has one documented home and no meaningful literal lives inside an
expression. Durations are in seconds unless the name says otherwise.
"""

from __future__ import annotations

# --- time units ----------------------------------------------------------
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 60 * SECONDS_PER_MINUTE
SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR

# --- session / storage ---------------------------------------------------
DEFAULT_SESSION_TTL_SECONDS = 30 * SECONDS_PER_MINUTE  # 30 min idle window
# Redis user-session index is kept slightly longer than the sessions it points
# at, so it never expires out from under a still-live session.
USER_INDEX_TTL_BUFFER_SECONDS = SECONDS_PER_HOUR

# --- tokens --------------------------------------------------------------
# JWT signing algorithm used by bearer tokens, signed email tokens, and the
# facade/runtime default.
DEFAULT_ALGORITHM = "HS256"
DEFAULT_ACCESS_TTL_SECONDS = 15 * SECONDS_PER_MINUTE
DEFAULT_REFRESH_TTL_DAYS = 30

# --- login lockout -------------------------------------------------------
DEFAULT_LOGIN_MAX_ATTEMPTS = 5
DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS = SECONDS_PER_MINUTE
DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS = SECONDS_PER_MINUTE
DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS = SECONDS_PER_HOUR
DEFAULT_LOGIN_ROUND_RETENTION_SECONDS = SECONDS_PER_HOUR

# --- sessions / csrf -----------------------------------------------------
DEFAULT_MAX_SESSIONS_PER_USER = 5
DEFAULT_SESSION_TIMEOUT_MINUTES = 30
DEFAULT_REMEMBER_ME_DAYS = 30
DEFAULT_CLEANUP_INTERVAL_MINUTES = 15
CSRF_TOKEN_BYTES = 32

# --- oauth / email flows -------------------------------------------------
OAUTH_STATE_TTL_SECONDS = 30 * SECONDS_PER_MINUTE
USED_TOKEN_TTL_SECONDS = 24 * SECONDS_PER_HOUR
DEFAULT_VERIFY_TTL_HOURS = 24
DEFAULT_RESET_TTL_HOURS = 1
DEFAULT_CHANGE_TTL_HOURS = 24

# --- registration throttle ----------------------------------------------
REGISTER_MAX_ATTEMPTS = 5
REGISTER_WINDOW_SECONDS = 10 * SECONDS_PER_MINUTE

# --- email-flow throttle -------------------------------------------------
# Per-target-email cap (in the service) stops email-bombing a victim even from
# rotating IPs; per-IP cap (at the edge) stops one caller spraying many addresses.
EMAIL_REQUEST_WINDOW_SECONDS = 5 * SECONDS_PER_MINUTE
EMAIL_REQUEST_MAX_PER_EMAIL = 3
EMAIL_REQUEST_MAX_PER_IP = 10

# --- password policy -----------------------------------------------------
MIN_PASSWORD_LENGTH = 8
