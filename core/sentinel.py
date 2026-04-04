"""
Sentinel PoW token generation for auth.openai.com.

Two strategies:
1. Local PoW: SHA3-512 brute-force (from codex_register/sentinel_pow.py)
2. Remote API: POST to sentinel.openai.com (original approach)

Local PoW is preferred as it's more reliable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import random
import time
import uuid
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

SENTINEL_URL = "https://sentinel.openai.com/backend-api/sentinel/req"

# PoW constants
DEFAULT_SENTINEL_DIFF = "0fffff"
DEFAULT_MAX_ITERATIONS = 500_000

_SCREEN_SIGNATURES = (3000, 3120, 4000, 4160)
_LANGUAGE_SIGNATURE = "en-US,es-US,en,es"
_NAVIGATOR_KEYS = ("location", "ontransitionend", "onprogress")
_WINDOW_KEYS = ("window", "document", "navigator")


def _format_browser_time() -> str:
    browser_now = datetime.now(timezone(timedelta(hours=-5)))
    return browser_now.strftime("%a %b %d %Y %H:%M:%S") + " GMT-0500 (Eastern Standard Time)"


def build_sentinel_config(user_agent: str) -> list:
    perf_ms = time.perf_counter() * 1000
    epoch_ms = (time.time() * 1000) - perf_ms
    return [
        random.choice(_SCREEN_SIGNATURES),
        _format_browser_time(),
        4294705152,
        0,
        user_agent,
        "",
        "",
        "en-US",
        _LANGUAGE_SIGNATURE,
        0,
        random.choice(_NAVIGATOR_KEYS),
        "location",
        random.choice(_WINDOW_KEYS),
        perf_ms,
        str(uuid.uuid4()),
        "",
        8,
        epoch_ms,
    ]


def _encode_pow_payload(config: list, nonce: int) -> bytes:
    prefix = (json.dumps(config[:3], separators=(",", ":"), ensure_ascii=False)[:-1] + ",").encode("utf-8")
    middle = (
        "," + json.dumps(config[4:9], separators=(",", ":"), ensure_ascii=False)[1:-1] + ","
    ).encode("utf-8")
    suffix = ("," + json.dumps(config[10:], separators=(",", ":"), ensure_ascii=False)[1:]).encode("utf-8")
    body = prefix + str(nonce).encode("ascii") + middle + str(nonce >> 1).encode("ascii") + suffix
    return base64.b64encode(body)


def solve_sentinel_pow(seed: str, difficulty: str, config: list,
                       max_iterations: int = DEFAULT_MAX_ITERATIONS) -> str | None:
    seed_bytes = seed.encode("utf-8")
    target = bytes.fromhex(difficulty)
    prefix_length = len(target)

    for nonce in range(max_iterations):
        encoded = _encode_pow_payload(config, nonce)
        digest = hashlib.sha3_512(seed_bytes + encoded).digest()
        if digest[:prefix_length] <= target:
            return encoded.decode("ascii")
    return None


def build_sentinel_pow_token(user_agent: str,
                             difficulty: str = DEFAULT_SENTINEL_DIFF,
                             max_iterations: int = DEFAULT_MAX_ITERATIONS) -> str:
    config = build_sentinel_config(user_agent)
    seed = format(random.random())
    solution = solve_sentinel_pow(seed, difficulty, config, max_iterations=max_iterations)
    if not solution:
        raise RuntimeError(f"PoW solve failed after {max_iterations} iterations")
    return f"gAAAAAC{solution}"


def get_sentinel_token(session, did: str, flow: str, user_agent: str) -> str | None:
    """
    Get sentinel token: build local PoW -> submit to sentinel API -> get token back.
    Falls back to local-only token if API fails.
    """
    try:
        pow_token = build_sentinel_pow_token(user_agent)
    except Exception as e:
        logger.warning("PoW generation failed: %s", e)
        pow_token = ""

    try:
        r = session.post(
            SENTINEL_URL,
            data=json.dumps({"p": pow_token, "id": did, "flow": flow}, separators=(",", ":")),
            headers={
                "Origin": "https://sentinel.openai.com",
                "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "Content-Type": "text/plain;charset=UTF-8",
            },
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("token")
    except Exception as e:
        logger.warning("sentinel API request failed: %s", e)

    # Fallback: return PoW token directly (some flows accept it)
    return pow_token or None
