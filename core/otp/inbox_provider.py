"""
InboxProvider — concrete OtpProvider wrapping the z069frame/otp-inbox HTTP API.

This is a direct re-homing of the logic that used to live in ``core/otp.py``.
Behavior for the ``otp-inbox`` backend is identical to the pre-refactor code:
same URL construction, same headers, same response parsing, same retry/poll
cadence, same exception-swallowing semantics.

The new :py:meth:`wait_for_code` / :py:meth:`peek` methods satisfy the
``OtpProvider`` protocol declared in ``core.otp`` and are built on top of
the unchanged inner ``fetch`` loop.
"""
from __future__ import annotations

import json
import logging
import math
import time
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

MAX_RETRIES = 8
RETRY_INTERVAL = 8  # seconds


# ---------------------------------------------------------------------------
# Legacy ad-hoc Protocol (kept for any importer that still referenced it)
# ---------------------------------------------------------------------------

@runtime_checkable
class OTPProvider(Protocol):
    """Legacy ad-hoc protocol — prefer ``core.otp.OtpProvider``."""

    def peek(self, email: str, domain: str) -> str | None: ...

    def fetch(
        self,
        email: str,
        domain: str,
        max_retries: int = MAX_RETRIES,
        retry_interval: float = RETRY_INTERVAL,
        skip_codes: "set | None" = None,
    ) -> str | None: ...


# ---------------------------------------------------------------------------
# InboxProvider
# ---------------------------------------------------------------------------

class InboxProvider:
    """OTP provider backed by the self-hosted z069frame/otp-inbox service.

    API contract preserved from the original ``core/otp.py``:
        GET {url_pattern}?to=<email>&otp_only=1&format=json
        Authorization: Bearer <token>

    Polling/retry/timeout are owned here; they are NOT caller-tunable
    on the new :py:meth:`wait_for_code` surface.
    """

    def __init__(
        self,
        token: str,
        url_pattern: str = "https://m.{domain}/api/latest",
        *,
        poll_interval: float = RETRY_INTERVAL,
        peek_http_timeout: float = 10.0,
        poll_http_timeout: float = 15.0,
    ):
        self.token = token
        self.url_pattern = url_pattern
        self._poll_interval = poll_interval
        self._peek_http_timeout = peek_http_timeout
        self._poll_http_timeout = poll_http_timeout

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

    @staticmethod
    def _domain_of(email: str) -> str:
        return email.split("@", 1)[1] if "@" in email else ""

    # -- New OtpProvider surface ------------------------------------------

    def peek(self, email: str) -> str | None:
        """Non-blocking single GET against the inbox API.

        Returns the current latest OTP for ``email`` or ``None`` on empty
        inbox / transport error / parse failure. Never raises for those.
        """
        return self.peek_with_domain(email, self._domain_of(email))

    def wait_for_code(
        self,
        email: str,
        *,
        timeout: float,
        skip_codes: "frozenset[str] | None" = None,
    ) -> str | None:
        """Block up to ``timeout`` seconds waiting for a fresh OTP.

        Uses the provider-owned poll interval. Returns the first OTP
        not in ``skip_codes``, or ``None`` on timeout.
        """
        if timeout <= 0:
            return None
        interval = max(self._poll_interval, 0.001)
        attempts = max(1, int(math.ceil(timeout / interval)))
        skip = set(skip_codes) if skip_codes else set()
        return self.fetch(
            email,
            self._domain_of(email),
            max_retries=attempts,
            retry_interval=interval,
            skip_codes=skip,
        )

    # -- Legacy surface (used by the fetch_otp/peek_otp shims) ------------

    def peek_with_domain(self, email: str, domain: str) -> str | None:
        """Legacy peek that takes an explicit domain argument."""
        url = self._build_url(email, domain)
        try:
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=self._peek_http_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            return self._parse_response(data)
        except Exception:
            return None

    def fetch(
        self,
        email: str,
        domain: str,
        max_retries: int = MAX_RETRIES,
        retry_interval: float = RETRY_INTERVAL,
        skip_codes: "set | None" = None,
    ) -> str | None:
        """Polling fetch loop — behavior-identical to pre-refactor ``otp.py``."""
        url = self._build_url(email, domain)
        headers = self._headers()
        skip = skip_codes or set()

        for attempt in range(1, max_retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self._poll_http_timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "ignore"))

                otp = self._parse_response(data)
                if otp:
                    if otp in skip:
                        logger.debug(
                            "OTP %s for %s is stale, skipping (attempt %d)",
                            otp, email, attempt,
                        )
                    else:
                        logger.info(
                            "OTP retrieved for %s (attempt %d): %s",
                            email, attempt, otp,
                        )
                        return otp

            except urllib.error.HTTPError as e:
                if e.code != 404:
                    logger.warning("OTP HTTP %d for %s", e.code, email)
            except Exception as e:
                logger.warning("OTP fetch error for %s: %s", email, e)

            if attempt < max_retries:
                logger.debug(
                    "OTP not ready for %s, retry %d/%d in %ss",
                    email, attempt, max_retries, retry_interval,
                )
                time.sleep(retry_interval)

        logger.error(
            "OTP fetch exhausted for %s after %d attempts",
            email, max_retries,
        )
        return None


# ---------------------------------------------------------------------------
# Legacy class alias — existing importers that reached into ``core.otp`` for
# ``MailServiceOTP`` still work. Prefer ``InboxProvider`` for new code.
# ---------------------------------------------------------------------------

MailServiceOTP = InboxProvider


__all__ = [
    "InboxProvider",
    "MailServiceOTP",
    "OTPProvider",
    "MAX_RETRIES",
    "RETRY_INTERVAL",
]
