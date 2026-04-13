"""
OTP provider package.

Public surface:
    OtpProvider          -- Protocol every backend satisfies.
    OtpError             -- base provider exception.
    OtpAuthError         -- credentials rejected.
    OtpTransportError    -- backend unreachable after internal retries.
    get_otp_provider(cfg)-- factory; reads config and returns a provider.

Legacy shims (deprecated, kept for Phase 2 back-compat):
    fetch_otp(email, domain, otp_token, max_retries, retry_interval, skip_codes)
    peek_otp(email, domain, otp_token)

Design doc: ~/Desktop/gptteam/notes/otp-protocol.md
"""
from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

from .inbox_provider import (
    InboxProvider,
    MailServiceOTP,  # legacy class, re-exported for any stray importer
    MAX_RETRIES,
    RETRY_INTERVAL,
)
from .mailbox_provider import MailboxProvider


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OtpError(Exception):
    """Base class for provider-side failures distinct from 'no code yet'."""


class OtpAuthError(OtpError):
    """Provider rejected our credentials (bad token, expired key)."""


class OtpTransportError(OtpError):
    """Network / backend unreachable after internal retries exhausted."""


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class OtpProvider(Protocol):
    """Abstraction over 'a thing that yields the latest OTP for an email'.

    See notes/otp-protocol.md §3 for the full contract.
    """

    def peek(self, email: str) -> str | None: ...

    def wait_for_code(
        self,
        email: str,
        *,
        timeout: float,
        skip_codes: "frozenset[str] | None" = None,
    ) -> str | None: ...


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _build_inbox_provider(sub_config: dict) -> OtpProvider:
    token = sub_config.get("token", "")
    url_pattern = sub_config.get("url_pattern", "https://m.{domain}/api/latest")
    poll_interval = float(sub_config.get("poll_interval_s", RETRY_INTERVAL))
    peek_timeout = float(sub_config.get("peek_timeout_s", 10))
    poll_http_timeout = float(sub_config.get("poll_http_timeout_s", 15))
    return InboxProvider(
        token=token,
        url_pattern=url_pattern,
        poll_interval=poll_interval,
        peek_http_timeout=peek_timeout,
        poll_http_timeout=poll_http_timeout,
    )


def _build_mailbox_provider(sub_config: dict) -> OtpProvider:
    return MailboxProvider(**sub_config)


_REGISTRY: "dict[str, Callable[[dict], OtpProvider]]" = {
    "inbox": _build_inbox_provider,
    "mailbox": _build_mailbox_provider,
}


def _legacy_synthesize(config: dict) -> dict:
    """Translate today's flat config.json shape into the namespaced form."""
    token = config.get("otp_token", "")
    url_pattern = config.get("otp_url_pattern", "https://m.{domain}/api/latest")
    return {
        "provider": config.get("otp_provider", "inbox"),
        "inbox": {
            "token": token,
            "url_pattern": url_pattern,
        },
    }


def get_otp_provider(config: dict) -> OtpProvider:
    """Build an OtpProvider from a config dict.

    Reads ``config["otp"]["provider"]`` (default ``"inbox"``). Provider-
    specific config lives under ``config["otp"][<provider>]``. If the
    top-level ``"otp"`` key is absent, falls back to the legacy flat
    keys (``otp_token``, ``otp_url_pattern``, ``otp_provider``) so that
    today's ``config.json`` still works.
    """
    otp_cfg = config.get("otp")
    if otp_cfg is None:
        otp_cfg = _legacy_synthesize(config)

    kind = otp_cfg.get("provider", "inbox")
    builder = _REGISTRY.get(kind)
    if builder is None:
        raise ValueError(f"unknown otp provider: {kind!r}")
    sub_config = otp_cfg.get(kind, {}) or {}
    return builder(sub_config)


# ---------------------------------------------------------------------------
# Legacy module-level shims (deprecated)
# ---------------------------------------------------------------------------
# deprecated: use get_otp_provider(config).wait_for_code
def fetch_otp(
    email: str,
    domain: str,
    otp_token: str,
    max_retries: int = MAX_RETRIES,
    retry_interval: float = RETRY_INTERVAL,
    skip_codes: "set | None" = None,
) -> str | None:
    """Legacy shim — delegates to the default InboxProvider's fetch loop.

    Kept so the existing ``from .otp import fetch_otp`` call site in
    ``core/openai_auth.py`` keeps working untouched. Caller migration
    to ``get_otp_provider(config).wait_for_code(...)`` is Phase 3.
    """
    provider = InboxProvider(token=otp_token)
    return provider.fetch(
        email,
        domain,
        max_retries=max_retries,
        retry_interval=retry_interval,
        skip_codes=skip_codes,
    )


# deprecated: use get_otp_provider(config).peek
def peek_otp(email: str, domain: str, otp_token: str) -> str | None:
    """Legacy shim — non-blocking single GET against the inbox API."""
    return InboxProvider(token=otp_token).peek_with_domain(email, domain)


__all__ = [
    "OtpProvider",
    "OtpError",
    "OtpAuthError",
    "OtpTransportError",
    "get_otp_provider",
    "InboxProvider",
    "MailboxProvider",
    "MailServiceOTP",
    "fetch_otp",
    "peek_otp",
    "MAX_RETRIES",
    "RETRY_INTERVAL",
]
