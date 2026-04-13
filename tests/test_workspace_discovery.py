"""Workspace discovery probes against ChatGPT backend-api.

Consolidated from the root-level spikes:
    test_workspace_api.py    (GET endpoint enumeration + cross-account invite)
    test_workspace_api2.py   (hardcoded AT, POST /accounts/check)
    test_workspace_api3.py   (every CPAB auth for a target email)
    test_workspace_api4.py   (full session AT via get_chatgpt_session_at)

All four flavors are preserved as separate test functions so their distinct
probe surface is retained. All hit live services and are gated behind
``@pytest.mark.live``; the default ``pytest`` run collects them but skips.

These remain operator-driven: they print diagnostic output and assert only
on the shape of the live responses. They are intentionally lenient — the
point is to probe the real ChatGPT accounts/check contract, not to enforce
a fixed schema.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import pytest

pytestmark = pytest.mark.live


# The canonical endpoint under probe. Preserved as a module constant so
# the migrated tests don't drift from the original spikes.
ACCOUNTS_CHECK_URL = "https://chatgpt.com/backend-api/accounts/check"

# A real team AT captured during the original spike (test_workspace_api2).
# Expires 2026-04-20; once stale, the test_workspace_api_hardcoded_at probe
# will fail at the auth boundary, which is fine — it's a spike.
HARDCODED_TEAM_AT = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE5MzQ0ZTY1LWJiYzktNDRkMS1hOWQwLWY5NTdiMDc5"
    "YmQwZSIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MSJ"
    "dLCJjbGllbnRfaWQiOiJhcHBfWDh6WTZ2VzJwUTl0UjNkRTduSzFqTDVnSCIsImV4cCI6MTc"
    "3NjgzMzU5NywiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS9hdXRoIjp7ImNoYXRncHRfYWNjb3V"
    "udF9pZCI6ImYwZDQ2OGE0LTUyMjQtNDhjMi1iMjZkLTZiYmIyZDBiZmY1NyIsImNoYXRncHR"
    "fYWNjb3VudF91c2VyX2lkIjoidXNlci1UUXpXdDN0RkdzTjFtMVlOOEZHQkJDaERfX2YwZDQ"
    "2OGE0LTUyMjQtNDhjMi1iMjZkLTZiYmIyZDBiZmY1NyIsImNoYXRncHRfY29tcHV0ZV9yZXN"
    "pZGVuY3kiOiJub19jb25zdHJhaW50IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJ0ZWFtIiwiY2h"
    "hdGdwdF91c2VyX2lkIjoidXNlci1UUXpXdDN0RkdzTjFtMVlOOEZHQkJDaEQiLCJ1c2VyX2l"
    "kIjoidXNlci1UUXpXdDN0RkdzTjFtMVlOOEZHQkJDaEQifSwiaHR0cHM6Ly9hcGkub3BlbmF"
    "pLmNvbS9wcm9maWxlIjp7ImVtYWlsIjoibGlzaHVhaTIwMjUxMkBnbWFpbC5jb20iLCJlbWF"
    "pbF92ZXJpZmllZCI6dHJ1ZX0sImlhdCI6MTc3NTk2OTU5NiwiaXNzIjoiaHR0cHM6Ly9hdXR"
    "oLm9wZW5haS5jb20iLCJqdGkiOiJjNTZmMzkxZC0zOGQwLTRlMGMtOTM4My1mMjRmZmI0Nzc"
    "2ZDEiLCJuYmYiOjE3NzU5Njk1OTYsInB3ZF9hdXRoX3RpbWUiOjE3NzQ5OTE3MzQ3ODQsInN"
    "jcCI6WyJvcGVuaWQiLCJlbWFpbCIsInByb2ZpbGUiLCJvZmZsaW5lX2FjY2VzcyIsIm1vZGV"
    "sLnJlcXVlc3QiLCJtb2RlbC5yZWFkIiwib3JnYW5pemF0aW9uLnJlYWQiLCJvcmdhbml6YXR"
    "pb24ud3JpdGUiXSwic2Vzc2lvbl9pZCI6ImF1dGhzZXNzX2dwTjFNcjRhME51cW9RN2JlWWw"
    "5dldURSIsInNsIjp0cnVlLCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwMzc1MTE4MDAzMzExNjM"
    "4MjkxMCJ9.r-9bjyhbLU6vnFGFMIBu-Ymwtxs6rZ9xc3nJcGdw8OISQMUUmOSx4dgPXZ0f0o"
    "aPktBoyh-FP38PqYTfMu6JlAfigw_WkpUX1YMizbDeJYYHi246qxckQdkUFO4KU3OWel6yW1"
    "Ra9cusmRZhLwRaOtWiw16CVRS9UYYpTj7PZmnyhxit-8SanQYaCxETFbin2XDYyuQ3eSrLX4"
    "S366Qq065mn3I9pXbUmYQD-pt02j8WPrKpOcj2fKC469i5xkORxQ68nuxFNLnnpTNiPlVuSk"
    "3o-GThaZIbE3ZbiQ_jZrT-0HqxkpRD5RDa0rtVfx5oTMzIQd0L2u0IkJ3vqDvaZMyo1XbRJ3"
    "i2ppffcTfl6XFspeF2927dkBSpsMCtAoo6SC7oNpWcT1uiwbstV_pwpoJIw1BrOgnbAoDwJ0"
    "M8jbOiR4ZzLs8jy7S3iJsP3iTsaZ0PPSbO6G6t6xG3dApmULuwTobIHSZ5AzYS6NWtqoFANQ"
    "uWDEdDJ-y2J-7fqXO9X4WThsmTN8WsofgZXCOmLFMXc9dQS6g8ooqknIB3dqmCccN2eflAWF"
    "mPmdF68PO8DJ02l5JY_B1YYhR2zODoQx7jIHVdXGGbF806mgMuG3oDoZzGCxKFjij3cfHRhJ"
    "OYbFPKufMkUcfFSU0MU8_P67nA8QBgEB7-RSqseq5_vqc"
)

TEST_EMAIL = "0403@010418.xyz"
INVITE_TARGET_EMAIL = "gooseltj@gmail.com"


def _headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
    }


def _proxies(proxy: Optional[str]) -> Optional[dict]:
    if not proxy:
        return None
    return {"https": proxy, "http": proxy}


def _api(method: str, url: str, access_token: str, proxy: Optional[str],
         body: Optional[dict] = None) -> tuple[int, str]:
    from curl_cffi import requests as cffi_requests  # live-only import

    kwargs = {
        "headers": _headers(access_token),
        "impersonate": "chrome136",
        "proxies": _proxies(proxy),
        "timeout": 30,
    }
    if method.upper() == "POST":
        r = cffi_requests.post(url, json=body or {}, **kwargs)
    else:
        r = cffi_requests.get(url, **kwargs)
    return r.status_code, r.text


def _cpa_admin(cfg: dict):
    from core.api import CPAAdmin  # live-only import
    cpa = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])
    if not cpa.login():
        pytest.skip("CPA admin login failed — cannot run live probe")
    return cpa


@pytest.fixture(scope="module")
def live_cfg() -> dict:
    from core import load_config
    return load_config()


# ---------------------------------------------------------------------------
# From test_workspace_api.py — enumerate a family of GETs + cross-account invite
# ---------------------------------------------------------------------------
def test_workspace_api_probe(live_cfg: dict) -> None:
    """Enumerate accounts endpoints for a team AT and probe cross-account invite."""
    from core.api import decode_jwt_claims  # live-only import
    proxy = live_cfg.get("proxy")

    cpa = _cpa_admin(live_cfg)
    auths = cpa.extract_codex_auths()
    target = next((a for a in auths if "0403" in a["email"]), None)
    if not target:
        target = next(
            (a for a in auths if a.get("plan_type") in ("team", "enterprise")), None
        )
    if not target:
        pytest.skip("No team/enterprise auth available in CPA-B")

    at = target["access_token"]
    email = target["email"]
    claims = decode_jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth", {})
    account_id = auth_info.get("chatgpt_account_id", "")

    print(f"Using: {email}  account_id={account_id}  AT len={len(at)}")
    assert account_id, "AT missing chatgpt_account_id claim"

    endpoints = [
        ("accounts/check", "https://chatgpt.com/backend-api/accounts/check"),
        ("me", "https://chatgpt.com/backend-api/me"),
        ("models", "https://chatgpt.com/backend-api/models?history_and_training_disabled=false"),
        ("account settings", f"https://chatgpt.com/backend-api/accounts/{account_id}/settings"),
        ("invites list", f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"),
        ("members", f"https://chatgpt.com/backend-api/accounts/{account_id}/members"),
        ("account info", f"https://chatgpt.com/backend-api/accounts/{account_id}"),
    ]
    for name, url in endpoints:
        status, text = _api("GET", url, at, proxy)
        print(f"[{name}] HTTP {status} ({len(text)} chars)")

    # Cross-account invite probe
    status, text = _api("GET", "https://chatgpt.com/backend-api/accounts/check", at, proxy)
    if status != 200:
        pytest.skip(f"accounts/check returned {status}")
    data = json.loads(text)
    accounts = data.get("accounts", {})
    assert isinstance(accounts, dict), "expected accounts to be a dict"
    for aid in accounts:
        if aid == account_id:
            continue
        url = f"https://chatgpt.com/backend-api/accounts/{aid}/invites"
        st, txt = _api("POST", url, at, proxy,
                       {"email_addresses": [INVITE_TARGET_EMAIL], "role": "standard-user"})
        print(f"cross-invite {aid}: HTTP {st} :: {txt[:200]}")


# ---------------------------------------------------------------------------
# From test_workspace_api2.py — hardcoded team AT POST accounts/check
# ---------------------------------------------------------------------------
def test_workspace_api_hardcoded_at(live_cfg: dict) -> None:
    """Use a known-good team AT (may have expired) to POST accounts/check."""
    from core.api import decode_jwt_claims
    proxy = live_cfg.get("proxy")

    claims = decode_jwt_claims(HARDCODED_TEAM_AT)
    auth = claims.get("https://api.openai.com/auth", {})
    current_aid = auth.get("chatgpt_account_id")
    print(f"Hardcoded AT: account_id={current_aid} plan={auth.get('chatgpt_plan_type')}")

    st, txt = _api("POST", ACCOUNTS_CHECK_URL, HARDCODED_TEAM_AT, proxy)
    print(f"POST accounts/check → HTTP {st} ({len(txt)} chars)")
    if st != 200:
        pytest.skip(f"hardcoded AT no longer accepted ({st}); expected once expired")

    data = json.loads(txt)
    accounts = data.get("accounts", {})
    assert isinstance(accounts, dict), "accounts must be a dict keyed by account_id"
    for aid in accounts:
        st2, txt2 = _api("GET", f"https://chatgpt.com/backend-api/accounts/{aid}/invites",
                         HARDCODED_TEAM_AT, proxy)
        print(f"  GET invites {aid}: HTTP {st2}")
        st3, txt3 = _api(
            "POST", f"https://chatgpt.com/backend-api/accounts/{aid}/invites",
            HARDCODED_TEAM_AT, proxy,
            {"email_addresses": [INVITE_TARGET_EMAIL], "role": "standard-user"},
        )
        print(f"  POST invite {aid}: HTTP {st3} :: {txt3[:160]}")


# ---------------------------------------------------------------------------
# From test_workspace_api3.py — try every auth for a target email
# ---------------------------------------------------------------------------
def test_workspace_api_per_auth(live_cfg: dict) -> None:
    """Pull every CPAB auth for a target email, probe each with accounts/check."""
    from core.api import decode_jwt_claims
    proxy = live_cfg.get("proxy")

    cpa = _cpa_admin(live_cfg)
    files = cpa.list_auth_files()
    auths = cpa.extract_codex_auths(files)
    target_auths = [a for a in auths if "0403" in a["email"]]
    if not target_auths:
        pytest.skip("no 0403@* auths available in CPA-B")

    print(f"Found {len(target_auths)} auth(s) for 0403@010418.xyz")

    for a in target_auths:
        at = a["access_token"]
        claims = decode_jwt_claims(at)
        auth_info = claims.get("https://api.openai.com/auth", {})
        current_aid = auth_info.get("chatgpt_account_id", "?")

        st, txt = _api("POST", ACCOUNTS_CHECK_URL, at, proxy)
        print(f"auth_id={a['auth_id']} account_id={current_aid} → HTTP {st}")
        if st != 200:
            continue

        data = json.loads(txt)
        accounts = data.get("accounts", {})
        for aid in accounts:
            if aid == current_aid:
                continue
            st2, txt2 = _api(
                "POST", f"https://chatgpt.com/backend-api/accounts/{aid}/invites",
                at, proxy,
                {"email_addresses": [INVITE_TARGET_EMAIL], "role": "standard-user"},
            )
            print(f"  other-account invite {aid}: HTTP {st2} :: {txt2[:160]}")


# ---------------------------------------------------------------------------
# From test_workspace_api4.py — full session AT from get_chatgpt_session_at
# ---------------------------------------------------------------------------
def test_workspace_api_session_at(live_cfg: dict) -> None:
    """Use a full-permission session AT to POST accounts/check + invite probes."""
    from core.api import decode_jwt_claims
    from core.chatgpt_session import get_chatgpt_session_at

    proxy = live_cfg.get("proxy")
    password = live_cfg["reg_password"]
    otp_token = live_cfg["otp_token"]

    print(f"Getting session AT for {TEST_EMAIL} ...")
    result = get_chatgpt_session_at(TEST_EMAIL, password, otp_token, proxy)
    if not result.get("ok"):
        pytest.skip(f"get_chatgpt_session_at failed: {result.get('error')}")

    at = result["access_token"]
    claims = decode_jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth", {})
    current_aid = auth_info.get("chatgpt_account_id", "?")
    print(f"session AT account_id={current_aid} plan={auth_info.get('chatgpt_plan_type')}")

    st, txt = _api("POST", ACCOUNTS_CHECK_URL, at, proxy)
    print(f"POST accounts/check → HTTP {st}")
    assert st == 200, f"accounts/check failed: {st} :: {txt[:300]}"

    data = json.loads(txt)
    accounts = data.get("accounts", {})
    for aid in accounts:
        st2, txt2 = _api(
            "POST", f"https://chatgpt.com/backend-api/accounts/{aid}/invites",
            at, proxy,
            {"email_addresses": [INVITE_TARGET_EMAIL], "role": "standard-user"},
        )
        tag = "CURRENT" if aid == current_aid else "OTHER"
        print(f"  [{tag}] invite {aid}: HTTP {st2} :: {txt2[:200]}")
