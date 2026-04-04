"""
OTP fetcher for self-hosted mail domains.
API: GET https://m.<domain>/api/latest?to=<email>&otp_only=1&format=json
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

MAX_RETRIES = 8
RETRY_INTERVAL = 8  # seconds


def peek_otp(email: str, domain: str, otp_token: str) -> str | None:
    """
    Non-blocking peek at the current latest OTP (no retry).
    Useful for detecting stale OTPs before triggering a new one.
    """
    url = f"https://m.{domain}/api/latest?to={email}&otp_only=1&format=json"
    headers = {"Authorization": f"Bearer {otp_token}"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        otp = None
        if isinstance(data, dict):
            otp = data.get("otp") or (data.get("item") or {}).get("otp")
        if isinstance(data, list) and data:
            otp = data[0].get("otp")
        return str(otp).strip() if otp else None
    except Exception:
        return None


def fetch_otp(email: str, domain: str, otp_token: str,
              max_retries: int = MAX_RETRIES,
              retry_interval: float = RETRY_INTERVAL,
              skip_codes: set | None = None) -> str | None:
    """
    Poll the OTP inbox API for a verification code.

    Args:
        skip_codes: set of OTP strings to ignore (e.g. stale codes from previous flows).
    Returns the OTP string or None.
    """
    url = f"https://m.{domain}/api/latest?to={email}&otp_only=1&format=json"
    headers = {"Authorization": f"Bearer {otp_token}"}
    skip = skip_codes or set()

    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))

            otp = None
            if isinstance(data, dict):
                otp = data.get("otp") or (data.get("item") or {}).get("otp")
            if isinstance(data, list) and data:
                otp = data[0].get("otp")

            if otp:
                otp = str(otp).strip()
                if otp in skip:
                    logger.debug("OTP %s for %s is stale, skipping (attempt %d)",
                                 otp, email, attempt)
                else:
                    logger.info("OTP retrieved for %s (attempt %d): %s", email, attempt, otp)
                    return otp

        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass  # mail not arrived yet
            else:
                logger.warning("OTP HTTP %d for %s", e.code, email)
        except Exception as e:
            logger.warning("OTP fetch error for %s: %s", email, e)

        if attempt < max_retries:
            logger.debug("OTP not ready for %s, retry %d/%d in %ds",
                         email, attempt, max_retries, retry_interval)
            time.sleep(retry_interval)

    logger.error("OTP fetch exhausted for %s after %d attempts", email, max_retries)
    return None
