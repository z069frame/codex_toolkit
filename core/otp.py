"""
OTP fetcher with pluggable provider support.

Default provider: MailServiceOTP — GET https://m.<domain>/api/latest
Future providers implement the same interface and are selected via
config.json ``otp_provider`` / ``otp_url_pattern`` keys.

Backward-compatible: module-level ``fetch_otp`` / ``peek_otp`` keep
the same signature so existing callers need no changes.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

MAX_RETRIES = 8
RETRY_INTERVAL = 8  # seconds


# ---------------------------------------------------------------------------
#  Provider interface
# ---------------------------------------------------------------------------

@runtime_checkable
class OTPProvider(Protocol):
    """Interface that any OTP backend must satisfy."""

    def peek(self, email: str, domain: str) -> str | None:
        """Single non-blocking attempt to get the latest OTP."""
        ...

    def fetch(self, email: str, domain: str,
              max_retries: int = MAX_RETRIES,
              retry_interval: float = RETRY_INTERVAL,
              skip_codes: set | None = None) -> str | None:
        """Poll for OTP with retries."""
        ...


# ---------------------------------------------------------------------------
#  Default provider — self-hosted mail service
# ---------------------------------------------------------------------------

class MailServiceOTP:
    """
    OTP provider using self-hosted mail service.
    API: GET https://m.<domain>/api/latest?to=<email>&otp_only=1&format=json

    Customizable via:
      - ``url_pattern``: Python format string with ``{domain}`` placeholder.
      - Subclassing ``_parse_response`` for different response shapes.
    """

    def __init__(self, token: str,
                 url_pattern: str = "https://m.{domain}/api/latest"):
        self.token = token
        self.url_pattern = url_pattern

    # -- Extension points --------------------------------------------------

    def _build_url(self, email: str, domain: str) -> str:
        base = self.url_pattern.format(domain=domain)
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}to={email}&otp_only=1&format=json"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def _parse_response(self, data) -> str | None:
        """Extract OTP string from API response payload."""
        otp = None
        if isinstance(data, dict):
            otp = data.get("otp") or (data.get("item") or {}).get("otp")
        elif isinstance(data, list) and data:
            otp = data[0].get("otp")
        return str(otp).strip() if otp else None

    # -- Public API --------------------------------------------------------

    def peek(self, email: str, domain: str) -> str | None:
        url = self._build_url(email, domain)
        try:
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            return self._parse_response(data)
        except Exception:
            return None

    def fetch(self, email: str, domain: str,
              max_retries: int = MAX_RETRIES,
              retry_interval: float = RETRY_INTERVAL,
              skip_codes: set | None = None) -> str | None:
        url = self._build_url(email, domain)
        headers = self._headers()
        skip = skip_codes or set()

        for attempt in range(1, max_retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8", "ignore"))

                otp = self._parse_response(data)
                if otp:
                    if otp in skip:
                        logger.debug("OTP %s for %s is stale, skipping (attempt %d)",
                                     otp, email, attempt)
                    else:
                        logger.info("OTP retrieved for %s (attempt %d): %s",
                                    email, attempt, otp)
                        return otp

            except urllib.error.HTTPError as e:
                if e.code != 404:
                    logger.warning("OTP HTTP %d for %s", e.code, email)
            except Exception as e:
                logger.warning("OTP fetch error for %s: %s", email, e)

            if attempt < max_retries:
                logger.debug("OTP not ready for %s, retry %d/%d in %ds",
                             email, attempt, max_retries, retry_interval)
                time.sleep(retry_interval)

        logger.error("OTP fetch exhausted for %s after %d attempts",
                     email, max_retries)
        return None


# ---------------------------------------------------------------------------
#  Module-level convenience (backward-compatible)
# ---------------------------------------------------------------------------

def peek_otp(email: str, domain: str, otp_token: str) -> str | None:
    """Non-blocking peek at the current latest OTP (no retry)."""
    return MailServiceOTP(otp_token).peek(email, domain)


def fetch_otp(email: str, domain: str, otp_token: str,
              max_retries: int = MAX_RETRIES,
              retry_interval: float = RETRY_INTERVAL,
              skip_codes: set | None = None) -> str | None:
    """Poll the OTP inbox API for a verification code."""
    return MailServiceOTP(otp_token).fetch(
        email, domain, max_retries, retry_interval, skip_codes,
    )
