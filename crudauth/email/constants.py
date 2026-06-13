"""Constants for the email flows."""

from __future__ import annotations

# Signed-token purposes (the ``purpose`` claim each flow's token carries).
VERIFY = "verify_email"
RESET = "reset_password"
CHANGE = "change_email"

# Per-target-email throttle actions -> the rate_limits keys they borrow.
VERIFY_ACTION = "email_verify_request"
RESET_ACTION = "password_reset_request"
CHANGE_ACTION = "email_change_request"

# Default frontend paths the signed-token links point at.
DEFAULT_VERIFY_PATH = "/verify-email"
DEFAULT_RESET_PATH = "/reset-password"
DEFAULT_CHANGE_PATH = "/confirm-email-change"

# Email subject lines.
SUBJECT_VERIFY = "Verify your email"
SUBJECT_RESET = "Reset your password"
SUBJECT_CHANGE = "Confirm your new email"
SUBJECT_EXISTING_ACCOUNT = "You already have an account"
