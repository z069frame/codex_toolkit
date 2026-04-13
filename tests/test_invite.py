"""Invite-endpoint role variant probe.

Migrated from root-level ``test_invite.py``. Tries two role variants against
``POST /backend-api/accounts/{id}/invites`` using a team AT pulled from CPA-B.

Live-API only. Skipped unless ``pytest -m live``.
"""

from __future__ import annotations

import json
from typing import Optional

import pytest

pytestmark = pytest.mark.live


INVITE_TARGET_EMAIL = "gooseltj@gmail.com"


def _proxies(proxy: Optional[str]) -> Optional[dict]:
    if not proxy:
        return None
    return {"https": proxy, "http": proxy}


def _try_invite_variants(access_token: str, account_id: str, email: str,
                         proxy: Optional[str]) -> tuple[Optional[dict], Optional[object]]:
    from curl_cffi import requests as cffi_requests

    base_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
    }
    candidates = [
        {
            "name": "invites_standard_user",
            "url": f"https://chatgpt.com/backend-api/accounts/{account_id}/invites",
            "body": {"email_addresses": [email], "role": "standard-user"},
        },
        {
            "name": "invites_account_admin",
            "url": f"https://chatgpt.com/backend-api/accounts/{account_id}/invites",
            "body": {"email_addresses": [email], "role": "account-admin"},
        },
    ]
    proxies = _proxies(proxy)
    for c in candidates:
        print(f"[{c['name']}] POST {c['url']}  body={json.dumps(c['body'])}")
        try:
            r = cffi_requests.post(
                c["url"], headers=base_headers, json=c["body"],
                impersonate="chrome136", proxies=proxies, timeout=30,
            )
            print(f"  HTTP {r.status_code} :: {r.text[:400]}")
            if r.status_code in (200, 201):
                return c, r
        except Exception as e:
            print(f"  ERROR: {e}")
    return None, None


def test_invite_role_variants() -> None:
    """POST /accounts/{id}/invites with role=standard-user then role=account-admin."""
    from core import load_config
    from core.api import CPAAdmin, decode_jwt_claims

    cfg = load_config()
    proxy = cfg.get("proxy")

    cpa = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])
    if not cpa.login():
        pytest.skip("CPA admin login failed")

    auths = cpa.extract_codex_auths(cpa.list_auth_files())
    team_auths = [a for a in auths if a.get("plan_type") in ("team", "enterprise", "business")]
    if not team_auths:
        pytest.skip("No team/enterprise/business auths available in CPA-B")

    for a in team_auths[:1]:
        claims = decode_jwt_claims(a["access_token"])
        auth_info = claims.get("https://api.openai.com/auth", {})
        account_id = auth_info.get("chatgpt_account_id", "")
        if not account_id:
            continue
        print(f"Testing invite to {INVITE_TARGET_EMAIL} using {a['email']} "
              f"(account_id={account_id}, plan={a.get('plan_type')})")
        winner, _ = _try_invite_variants(a["access_token"], account_id,
                                          INVITE_TARGET_EMAIL, proxy)
        if winner:
            print(f"WINNER: {winner['name']}")
        else:
            print(f"All variants failed for {a['email']}")
