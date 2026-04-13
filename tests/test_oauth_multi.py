"""Multi-workspace OAuth flow probes.

Consolidated from:
    test_oauth_multi.py       — happy-path ``oauth_login_multi`` run
    test_oauth_multi_debug.py — low-level cookie/session trace across two
                                consecutive ``authorize`` iterations

Live-API only. Skipped unless ``pytest -m live``.
"""

from __future__ import annotations

import json
import os

import pytest

pytestmark = pytest.mark.live


DEFAULT_EMAIL = os.environ.get("CODEX_TEST_EMAIL", "0403@010418.xyz")


def _dump_cookies(session, label: str) -> None:
    from core.openai_auth import _decode_auth_cookie, _get_cookie

    auth_cookie = _get_cookie(session, "oai-client-auth-session")
    print(f"\n--- cookies after {label} ---")
    for c in session.cookies.jar:
        name = c.name.lower()
        if "auth" in name or "workspace" in name or "_session" in name:
            val = c.value
            preview = val[:60] + "..." if len(val) > 60 else val
            print(f"  {c.name} = {preview}")
    if auth_cookie:
        data = _decode_auth_cookie(auth_cookie)
        print("  [decoded oai-client-auth-session]")
        for k, v in data.items():
            if isinstance(v, list):
                print(f"    {k}: [{len(v)} items]")
                for item in v[:3]:
                    print(f"      - {item}")
            else:
                print(f"    {k}: {v}")


def test_oauth_multi_flow() -> None:
    """End-to-end ``oauth_login_multi`` call; reports per-workspace results."""
    from core import load_config
    from core.api import CPAAdmin
    from core.openai_auth import oauth_login_multi

    cfg = load_config()
    proxy = cfg.get("proxy")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]

    cpa = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])
    if not cpa.login():
        pytest.skip("CPA admin login failed")

    def start_fn():
        r = cpa.start_oauth()
        print(f"  [start_oauth] url={(r.get('url') or '')[:80]}... "
              f"state={(r.get('state') or '')[:12]}...")
        return r

    def log_fn(msg):
        print(msg)

    result = oauth_login_multi(
        start_oauth_fn=start_fn,
        email=DEFAULT_EMAIL,
        password=password,
        otp_token=otp_token,
        proxy=proxy,
        workspace_filter=None,
        log_fn=log_fn,
    )

    print(f"ok={result.get('ok')}  error={result.get('error')}")
    workspaces = result.get("workspaces") or []
    results = result.get("results") or []
    print(f"workspaces discovered: {len(workspaces)}")
    for w in workspaces:
        print(f"  • {w.get('name')} (kind={w.get('kind')}, id={w.get('id')})")
    print(f"per-workspace results: {len(results)}")
    for r in results:
        tag = "OK" if r.get("ok") else "FAIL"
        print(f"  [{tag}] {r.get('workspace_name')} "
              f"({r.get('workspace_kind')}, id={r.get('workspace_id')}) "
              f"err={r.get('error')}")
    assert "ok" in result, "oauth_login_multi must return a dict with 'ok'"


def test_oauth_multi_cookie_trace() -> None:
    """Low-level trace across two ``authorize`` iterations for diagnostics."""
    from core import load_config
    from core.api import CPAAdmin
    from core.openai_auth import (
        AUTH_BASE, WORKSPACE_URL,
        _create_session, _decode_auth_cookie, _do_login_phase,
        _follow_redirects, _get_cookie,
    )

    cfg = load_config()
    proxy = cfg.get("proxy")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]

    cpa = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])
    if not cpa.login():
        pytest.skip("CPA admin login failed")

    session, _ = _create_session(proxy)
    try:
        # Iteration 1: full login + select workspace A
        print("=" * 70)
        print("ITERATION 1")
        print("=" * 70)
        start1 = cpa.start_oauth()
        r = session.get(start1["url"], timeout=30)
        print(f"GET authorize → {r.status_code} {r.url[:120]}")
        _dump_cookies(session, "GET authorize")

        ok, err = _do_login_phase(session, DEFAULT_EMAIL, password, otp_token)
        print(f"login ok={ok}  err={err}")
        _dump_cookies(session, "login complete")

        auth_cookie = _get_cookie(session, "oai-client-auth-session")
        if not auth_cookie:
            pytest.skip("no oai-client-auth-session cookie after login")
        workspaces = _decode_auth_cookie(auth_cookie).get("workspaces", [])
        print(f"workspaces: {len(workspaces)}")
        if len(workspaces) < 1:
            pytest.skip("account has no workspaces to probe")

        ws_a = workspaces[0]
        print(f"select workspace A: {ws_a.get('name')} id={ws_a.get('id')}")
        r = session.post(
            WORKSPACE_URL,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
            },
            data=json.dumps({"workspace_id": ws_a["id"]}),
            timeout=30,
        )
        print(f"POST workspace → {r.status_code} :: {r.text[:300]}")
        cont1 = r.json().get("continue_url", "") if r.ok else ""
        if cont1:
            code1, _ = _follow_redirects(session, cont1)
            print(f"follow continue_url → code_len={len(code1) if code1 else 0}")
        _dump_cookies(session, "after iter1")

        if len(workspaces) < 2:
            print("only one workspace; skipping iter2")
            return

        # Iteration 2: fresh authorize, reuse session
        print("=" * 70)
        print("ITERATION 2")
        print("=" * 70)
        start2 = cpa.start_oauth()
        r = session.get(start2["url"], timeout=30)
        print(f"GET authorize → {r.status_code} final={r.url[:150]}")
        _dump_cookies(session, "iter2 GET authorize")

        ws_b = workspaces[1]
        print(f"select workspace B: {ws_b.get('name')} id={ws_b.get('id')}")
        r = session.post(
            WORKSPACE_URL,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
            },
            data=json.dumps({"workspace_id": ws_b["id"]}),
            timeout=30,
        )
        print(f"POST workspace → {r.status_code} :: {r.text[:500]}")
    finally:
        session.close()
