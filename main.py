#!/usr/bin/env python3
"""
codex_toolkit — unified registration + OAuth for Codex accounts.

Usage:
  python main.py register [--count N]     # register N new accounts (default 1)
  python main.py oauth                    # pick 1 candidate and do OAuth
  python main.py register --help
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import datetime

from core import load_config
from core.api import CPAAdmin, CPAMgmt, DataManager, decode_jwt_claims, check_deactivated
from core.email_gen import generate_email
from core.openai_auth import register_account, oauth_login
from core.chatgpt_session import get_chatgpt_session_at, get_chatgpt_full_tokens

LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format=LOG_FMT, level=level, stream=sys.stderr)


# ---------------------------------------------------------------------------
#  register command
# ---------------------------------------------------------------------------


def cmd_register(cfg, args):
    count = args.count or 1
    proxy = (getattr(args, "proxy", None) or cfg.get("proxy")) or None
    if getattr(args, "proxy", None):
        print(f"🌐 proxy override: {args.proxy.split('@')[-1] if '@' in args.proxy else args.proxy}")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    client_id = cfg["oauth_client_id"]
    redirect_uri = cfg["oauth_redirect_uri"]
    domains = cfg["domains"]
    output_dir = os.path.join(os.path.dirname(__file__), cfg.get("output_dir", "output"))
    os.makedirs(output_dir, exist_ok=True)

    # Explicit email overrides generation and clamps count to 1
    fixed_email = (args.email or "").strip() or None
    if fixed_email:
        if count != 1:
            print(f"⚠️  --email provided, forcing count=1 (was {count})")
        count = 1

    # Explicit domain: auto-generate prefix on that domain (ignored if --email set)
    fixed_domain = (args.domain or "").strip().lstrip("@") or None
    if fixed_domain and fixed_email:
        print(f"⚠️  --domain ignored because --email is set")
        fixed_domain = None

    # Init API clients
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    cpa_mgmt = CPAMgmt(cfg["cpa_mgmt_base"], cfg["cpa_mgmt_bearer"])

    results = []
    for i in range(count):
        email = fixed_email or generate_email(domains, domain=fixed_domain)
        print(f"\n{'='*60}")
        print(f"[{i+1}/{count}] Registering {email}")
        print(f"{'='*60}")

        # Phase 1: Register at auth.openai.com
        reg = register_account(
            email=email,
            password=password,
            otp_token=otp_token,
            client_id=client_id,
            redirect_uri=redirect_uri,
            proxy=proxy,
        )

        phone_required = False
        at = ""
        rt = ""

        if not reg["ok"]:
            err_msg = reg.get("error", "")
            print(f"  ❌ Registration failed: {err_msg}")
            results.append({"email": email, "ok": False, "stage": "register", "error": err_msg})
            continue
        else:
            phone_required = reg.get("phone_required", False)
            at = reg["access_token"]
            rt = reg["refresh_token"]

            if phone_required:
                print(f"  ⚠️  Phone required — trying ChatGPT session for AT...")
                sess_result = get_chatgpt_session_at(email, password, otp_token, proxy)
                if sess_result["ok"]:
                    at = sess_result["access_token"]
                    print(f"  ✅ ChatGPT session AT obtained (len={len(at)})")
                else:
                    print(f"  ⚠️  ChatGPT session failed: {sess_result['error']}")
            else:
                print(f"  ✅ Registered — AT length: {len(at)}, RT length: {len(rt)}")

        # Phase 1.5: Get ChatGPT full tokens (AT + RT) via PKCE OAuth
        chatgpt_at = ""
        chatgpt_rt = ""
        use_rt = getattr(args, "rt", False)
        if use_rt:
            print(f"  → Getting ChatGPT RT via full PKCE OAuth...")
            rt_result = get_chatgpt_full_tokens(email, password, otp_token, proxy)
            if rt_result["ok"]:
                chatgpt_at = rt_result["access_token"]
                chatgpt_rt = rt_result["refresh_token"]
                print(f"  ✅ ChatGPT tokens: AT len={len(chatgpt_at)}, RT len={len(chatgpt_rt)}")
                # Use ChatGPT AT for DM (better scopes) if we don't already have one
                if not at:
                    at = chatgpt_at
                # Save ChatGPT tokens to separate file
                rt_file = os.path.join(output_dir, f"{email}.chatgpt.json")
                with open(rt_file, "w") as f:
                    json.dump({
                        "email": email,
                        "access_token": chatgpt_at,
                        "refresh_token": chatgpt_rt,
                        "id_token": rt_result.get("id_token", ""),
                        "expires_in": rt_result.get("expires_in"),
                        "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
                        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                    }, f, indent=2)
                print(f"  💾 ChatGPT tokens → {rt_file}")
            else:
                print(f"  ⚠️  ChatGPT RT failed: {rt_result['error']}")

        # Save credentials locally (always, even without tokens)
        token_file = os.path.join(output_dir, f"{email}.json")
        with open(token_file, "w") as f:
            json.dump({
                "email": email,
                "password": password,
                "access_token": at,
                "refresh_token": rt,
                "chatgpt_refresh_token": chatgpt_rt,
                "phone_required": phone_required,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            }, f, indent=2)

        dm_ok = False
        cpa_ok = False

        # Phase 2: Create account in Data Manager
        if at:
            claims = decode_jwt_claims(at)
            account_id = claims.get("sub", "")
            dm_result = dm.create_account(email, password, at, account_id,
                                          token_context="free")
        else:
            # No AT — still create in DM with token_context=unknown for future relogin
            dm_result = dm.create_account(email, password, access_token="", account_id="",
                                          token_context="unknown")

        dm_ok = dm_result.get("ok", False)
        if dm_ok:
            tc_label = "unknown" if not at else "free"
            print(f"  ✅ DM created (token_context={tc_label})")
        else:
            print(f"  ⚠️  DM create failed: {dm_result}")

        # Verify DM
        dm_check = dm.find_account(email)
        if dm_check:
            print(f"  ✅ DM verified — id={dm_check.get('id')}")
        else:
            print(f"  ⚠️  DM verify: not found (non-fatal)")

        # Phase 3: populate CPA-Free with the auth token — but only when we
        # have a real Codex-client AT. ChatGPT NextAuth session AT
        # (phone-blocked fallback) is rejected by /backend-api/codex/* with
        # 401, so uploading it just pollutes the pool. Phone-blocked
        # accounts stay in DM awaiting Team upgrade via oauth-multi.
        cpa_ok = False
        if at and not phone_required:
            print(f"  → Starting CPA OAuth (free token)...")
            oauth_result = _do_cpa_mgmt_oauth(cpa_mgmt, email, password, otp_token, proxy)
            cpa_ok = oauth_result.get("ok", False)
            if cpa_ok:
                print(f"  ✅ CPA OAuth complete (with refresh_token)")
            else:
                err = str(oauth_result.get("error", ""))
                print(f"  ⚠️  CPA OAuth failed: {err[:200]}")

            # Fallback: direct upload of the real PKCE Codex AT we already have
            if not cpa_ok:
                print(f"  → Uploading PKCE AT to CPA-Free...")
                up = cpa_mgmt.upload_codex_auth(email=email, access_token=at,
                                                 refresh_token=rt)
                cpa_ok = up.get("ok", False)
                if cpa_ok:
                    cpa_mgmt.set_priority(up["name"], 100)
                    cpa_mgmt.set_websockets(up["name"], True)
                    print(f"  ✅ CPA upload: {up['name']} (priority=100, ws=on)")
                else:
                    print(f"  ⚠️  CPA upload failed: {up.get('error') or up.get('status')}")
        elif at:
            print(f"  ⏭️ Skipping CPA upload — no Codex-client AT "
                  f"(phone-blocked); account waits in DM for Team upgrade")

        results.append({
            "email": email,
            "ok": True,
            "phone_required": phone_required,
            "has_at": bool(at),
            "dm_ok": dm_ok,
            "cpa_ok": cpa_ok,
        })

    # Summary
    print(f"\n{'='*60}")
    ok_count = sum(1 for r in results if r["ok"])
    at_count = sum(1 for r in results if r.get("has_at"))
    phone_count = sum(1 for r in results if r.get("phone_required"))
    print(f"Summary: {ok_count}/{len(results)} registered, {at_count} got AT"
          + (f", {phone_count} phone fallback" if phone_count else ""))
    for r in results:
        status = "✅" if r["ok"] else "❌"
        extras = ""
        if r["ok"]:
            if r.get("phone_required"):
                at_s = "✅" if r.get("has_at") else "❌"
                dm_s = "✅" if r.get("dm_ok") else "⚠️"
                extras = f" 📱→AT:{at_s} DM:{dm_s}"
            else:
                dm_s = "✅" if r.get("dm_ok") else "⚠️"
                cpa_s = "✅" if r.get("cpa_ok") else "⚠️"
                extras = f" DM:{dm_s} CPA:{cpa_s}"
        else:
            extras = f" — {r.get('error', '')}"
        print(f"  {status} {r['email']}{extras}")


def _do_cpa_mgmt_oauth(cpa_mgmt: CPAMgmt, email: str, password: str,
                        otp_token: str, proxy: str | None) -> dict:
    """Get OAuth URL from CPA management, complete login, send callback."""
    url_resp = cpa_mgmt.get_oauth_url()
    if not url_resp.get("ok"):
        return {"ok": False, "error": f"get_oauth_url: {url_resp}"}

    oauth_url = url_resp.get("url")
    cpa_state = url_resp.get("state")
    if not oauth_url:
        return {"ok": False, "error": "no_oauth_url_returned"}

    code, state, err = oauth_login(oauth_url, email, password, otp_token, proxy)
    if not code:
        return {"ok": False, "error": f"oauth_login: {err}"}

    cb_resp = cpa_mgmt.oauth_callback(state or cpa_state, code)
    return {"ok": cb_resp.get("ok", False), "callback": cb_resp}


# ---------------------------------------------------------------------------
#  oauth command
# ---------------------------------------------------------------------------


def cmd_oauth(cfg, args):
    proxy = (getattr(args, "proxy", None) or cfg.get("proxy")) or None
    if getattr(args, "proxy", None):
        print(f"🌐 proxy override: {args.proxy.split('@')[-1]}")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]

    # Init API clients
    cpa_admin = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    # Login CPA
    if not cpa_admin.login():
        print("❌ CPA admin login failed")
        return

    # Pick candidates
    if args.email:
        acc = dm.find_account(args.email)
        if not acc:
            print(f"❌ Account not found in DM: {args.email}")
            return
        candidates = [acc]
    else:
        candidates = dm.pick_oauth_candidates(cpa_admin, args.count)
        if not candidates:
            print("⏭️  No OAuth candidate found, skipping")
            return

    results = []
    for i, candidate in enumerate(candidates):
        email = candidate.get("email", "")
        acc_id = candidate.get("id", "?")
        category = candidate.get("category", "?")

        print(f"\n{'='*60}")
        print(f"[{i+1}/{len(candidates)}] OAuth: {email} (id={acc_id}, category={category})")
        print(f"{'='*60}")

        # Start OAuth via CPA admin
        start = cpa_admin.start_oauth()
        if not start.get("ok"):
            print(f"  ❌ CPA start_oauth failed: {start}")
            results.append({"email": email, "ok": False, "error": f"start_oauth: {start}"})
            continue

        oauth_url = start.get("url")
        cpa_state = start.get("state")
        if not oauth_url:
            print(f"  ❌ No OAuth URL returned: {start}")
            results.append({"email": email, "ok": False, "error": "no_oauth_url"})
            continue

        print(f"  → OAuth URL obtained, completing login...")

        # Complete OAuth login
        code, state, err = oauth_login(oauth_url, email, password, otp_token, proxy)
        if not code:
            print(f"  ❌ OAuth login failed: {err}")
            results.append({"email": email, "ok": False, "error": f"oauth_login: {err}"})
            continue

        print(f"  ✅ OAuth login complete, sending callback...")

        # Send callback to CPA
        cb_resp = cpa_admin.oauth_callback(state or cpa_state, code)
        if not cb_resp.get("ok"):
            print(f"  ❌ Callback failed: {cb_resp}")
            results.append({"email": email, "ok": False, "error": f"callback: {cb_resp}"})
            continue

        print(f"  ✅ Callback sent")

        # Verify: find auth file in CPA
        auth = cpa_admin.find_auth_by_email(email)
        auth_ok = False
        if not auth:
            print(f"  ⚠️  Auth file not found in CPA for {email} (may take a moment)")
        else:
            auth_id = auth.get("id")
            has_at = auth.get("has_at")
            has_rt = auth.get("has_rt")
            plan = auth.get("plan_type", "?")
            print(f"  ✅ Verified: auth_id={auth_id}, AT:{has_at}, RT:{has_rt}, plan:{plan}")
            auth_ok = True

            # Set priority
            if cpa_admin.set_priority(auth_id, 100):
                print(f"  ✅ Priority set to 100")
            else:
                print(f"  ⚠️  Priority update failed")

        print(f"\n  ✅ {email} ({category}) — OAuth complete")
        results.append({
            "email": email,
            "ok": True,
            "category": category,
            "verified": auth_ok,
        })

    # Summary
    print(f"\n{'='*60}")
    ok_count = sum(1 for r in results if r["ok"])
    print(f"OAuth summary: {ok_count}/{len(results)} succeeded")
    for r in results:
        status_icon = "✅" if r["ok"] else "❌"
        if r["ok"]:
            v = "✅" if r.get("verified") else "⚠️"
            print(f"  {status_icon} {r['email']} ({r.get('category','?')}) verified:{v}")
        else:
            print(f"  {status_icon} {r['email']} — {r.get('error', '')}")


# ---------------------------------------------------------------------------
#  session command — get full-permission ChatGPT AT
# ---------------------------------------------------------------------------


def cmd_session(cfg, args):
    proxy = (getattr(args, "proxy", None) or cfg.get("proxy")) or None
    if getattr(args, "proxy", None):
        print(f"🌐 proxy override: {args.proxy.split('@')[-1]}")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    output_dir = os.path.join(os.path.dirname(__file__), cfg.get("output_dir", "output"))
    os.makedirs(output_dir, exist_ok=True)

    email = args.email
    if not email:
        # Try to find the latest registered account
        files = sorted(
            [f for f in os.listdir(output_dir)
             if f.endswith(".json") and not f.endswith(".session.json")],
            key=lambda x: os.path.getmtime(os.path.join(output_dir, x)),
            reverse=True,
        )
        if not files:
            print("❌ No registered accounts found. Specify --email or register first.")
            return
        email = files[0].replace(".json", "")
        print(f"Auto-selected: {email}")

    print(f"\n{'='*60}")
    print(f"Getting ChatGPT full-permission AT for: {email}")
    print(f"{'='*60}\n")

    result = get_chatgpt_session_at(email, password, otp_token, proxy)

    if not result["ok"]:
        print(f"❌ Failed: {result['error']}")
        return

    at = result["access_token"]
    session_cookie = result["session_cookie"]

    # Decode JWT for display
    scopes = []
    client_id = ""
    plan_type = ""
    account_id = ""
    try:
        claims = decode_jwt_claims(at)
        scopes = claims.get("scp", [])
        client_id = claims.get("client_id", "")
        auth_info = claims.get("https://api.openai.com/auth", {})
        plan_type = auth_info.get("chatgpt_plan_type", "")
        account_id = auth_info.get("chatgpt_account_id", "")
    except Exception:
        pass

    print(f"✅ Success!")
    print(f"  AT length:      {len(at)}")
    print(f"  Cookie length:  {len(session_cookie)}")
    print(f"  Client ID:      {client_id}")
    print(f"  Scopes:         {scopes}")
    print(f"  Plan:           {plan_type}")
    print(f"  Account ID:     {account_id}")
    print(f"  User:           {result.get('user', {}).get('email', '')}")
    print(f"  Expires:        {result.get('expires', '')}")

    # Save to output/<email>.session.json
    session_file = os.path.join(output_dir, f"{email}.session.json")
    with open(session_file, "w") as f:
        json.dump({
            "email": email,
            "access_token": at,
            "session_cookie": session_cookie,
            "client_id": client_id,
            "scopes": scopes,
            "plan_type": plan_type,
            "account_id": account_id,
            "user": result.get("user", {}),
            "expires": result.get("expires"),
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        }, f, indent=2)
    print(f"\n  💾 Saved to: {session_file}")


# ---------------------------------------------------------------------------
#  dm-writeback command — get team AT and write back to DM
# ---------------------------------------------------------------------------


def cmd_dm_writeback(cfg, args):
    proxy = (getattr(args, "proxy", None) or cfg.get("proxy")) or None
    if getattr(args, "proxy", None):
        print(f"🌐 proxy override: {args.proxy.split('@')[-1]}")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    output_dir = os.path.join(os.path.dirname(__file__), cfg.get("output_dir", "output"))
    os.makedirs(output_dir, exist_ok=True)

    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    # ── Pick candidates ──
    if args.email:
        acc = dm.find_account(args.email)
        if not acc:
            print(f"❌ Account not found in DM: {args.email}")
            return
        candidates = [acc]
    else:
        candidates = dm.pick_writeback_candidates(args.count)
        if not candidates:
            print("⏭️  No writeback candidate (need enterprise/business with token_context=free)")
            return

    results = []
    for i, candidate in enumerate(candidates):
        email = candidate.get("email", "")
        acc_id = candidate.get("id")
        category = candidate.get("category", "?")
        token_context = candidate.get("token_context", "?")
        status = candidate.get("status", "?")

        print(f"\n{'='*60}")
        print(f"[{i+1}/{len(candidates)}] DM Writeback: {email}")
        print(f"  id={acc_id}  category={category}  token_context={token_context}  status={status}")
        print(f"{'='*60}\n")

        # ── Get team session AT ──
        print(f"  → Getting ChatGPT session AT...")
        result = get_chatgpt_session_at(email, password, otp_token, proxy)

        if not result["ok"]:
            print(f"  ❌ Session AT failed: {result['error']}")
            results.append({"email": email, "ok": False, "error": result["error"]})
            continue

        at = result["access_token"]

        # Decode JWT to determine plan type
        claims = decode_jwt_claims(at)
        scopes = claims.get("scp", [])
        auth_info = claims.get("https://api.openai.com/auth", {})
        plan_type = auth_info.get("chatgpt_plan_type", "")
        account_id = auth_info.get("chatgpt_account_id", "")

        print(f"  ✅ Session AT obtained (len={len(at)})")
        print(f"     plan={plan_type}  scopes={len(scopes)}  account_id={account_id}")

        # Determine token_context to write back
        new_token_context = "team" if plan_type in ("team", "enterprise", "business") else "free"
        print(f"     token_context: {token_context} → {new_token_context}")

        # ── PATCH DM ──
        print(f"  → Writing back to DM (PATCH /admin/accounts/{acc_id})...")
        patch_body = {
            "access_token": at,
            "token_context": new_token_context,
        }
        if account_id:
            patch_body["account_id"] = account_id

        patch_result = dm.patch_account(acc_id, patch_body)
        if not patch_result.get("ok"):
            print(f"  ❌ PATCH failed: {patch_result}")
            results.append({"email": email, "ok": False, "error": f"patch_failed: {patch_result}"})
            continue

        print(f"  ✅ DM PATCH success")

        # ── Verify ──
        print(f"  → Verifying writeback...")
        verify = dm.find_account(email)
        if not verify:
            print(f"  ⚠️  Verify: account not found (non-fatal)")
        else:
            v_tc = verify.get("token_context", "?")
            v_at = verify.get("access_token", "")
            at_match = v_at[:20] == at[:20] if v_at and at else False
            print(f"  ✅ Verified: token_context={v_tc}, AT match={at_match}")

        # ── Save session locally ──
        session_file = os.path.join(output_dir, f"{email}.session.json")
        with open(session_file, "w") as f:
            json.dump({
                "email": email,
                "access_token": at,
                "session_cookie": result.get("session_cookie", ""),
                "plan_type": plan_type,
                "token_context": new_token_context,
                "account_id": account_id,
                "scopes": scopes,
                "user": result.get("user", {}),
                "expires": result.get("expires"),
                "dm_id": acc_id,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            }, f, indent=2)
        print(f"  💾 Saved to: {session_file}")

        print(f"\n  ✅ {email} ({category}) — writeback complete ({token_context} → {new_token_context})")
        results.append({
            "email": email,
            "ok": True,
            "token_context": new_token_context,
            "plan_type": plan_type,
        })

    # Summary
    print(f"\n{'='*60}")
    ok_count = sum(1 for r in results if r["ok"])
    print(f"DM Writeback summary: {ok_count}/{len(results)} succeeded")
    for r in results:
        status_icon = "✅" if r["ok"] else "❌"
        if r["ok"]:
            print(f"  {status_icon} {r['email']} → token_context={r['token_context']} (plan={r['plan_type']})")
        else:
            print(f"  {status_icon} {r['email']} — {r.get('error', '')}")


# ---------------------------------------------------------------------------
#  relogin command — re-login unknown accounts to get free AT
# ---------------------------------------------------------------------------


def cmd_relogin(cfg, args):
    proxy = (getattr(args, "proxy", None) or cfg.get("proxy")) or None
    if getattr(args, "proxy", None):
        print(f"🌐 proxy override: {args.proxy.split('@')[-1]}")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    output_dir = os.path.join(os.path.dirname(__file__), cfg.get("output_dir", "output"))
    os.makedirs(output_dir, exist_ok=True)

    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    # ── Pick candidates ──
    if args.email:
        acc = dm.find_account(args.email)
        if not acc:
            print(f"❌ Account not found in DM: {args.email}")
            return
        candidates = [acc]
    else:
        count = args.count or 1
        candidates = dm.pick_relogin_candidates(count)
        if not candidates:
            print("⏭️  No relogin candidates (need token_context=unknown)")
            return

    results = []
    for i, candidate in enumerate(candidates):
        email = candidate.get("email", "")
        acc_id = candidate.get("id")
        category = candidate.get("category", "?")
        token_context = candidate.get("token_context", "?")
        status = candidate.get("status", "?")

        print(f"\n{'='*60}")
        print(f"[{i+1}/{len(candidates)}] Relogin: {email}")
        print(f"  id={acc_id}  category={category}  token_context={token_context}  status={status}")
        print(f"{'='*60}\n")

        # ── Get free AT via ChatGPT session ──
        print(f"  → Getting ChatGPT session AT...")
        result = get_chatgpt_session_at(email, password, otp_token, proxy)

        if not result["ok"]:
            print(f"  ❌ Session AT failed: {result['error']}")
            results.append({"email": email, "ok": False, "error": result["error"]})
            continue

        at = result["access_token"]

        # Decode JWT
        claims = decode_jwt_claims(at)
        scopes = claims.get("scp", [])
        auth_info = claims.get("https://api.openai.com/auth", {})
        plan_type = auth_info.get("chatgpt_plan_type", "")
        account_id = auth_info.get("chatgpt_account_id", "")

        print(f"  ✅ Session AT obtained (len={len(at)})")
        print(f"     plan={plan_type}  scopes={len(scopes)}  account_id={account_id}")

        # Determine token_context
        new_token_context = "team" if plan_type in ("team", "enterprise", "business") else "free"
        print(f"     token_context: {token_context} → {new_token_context}")

        # ── PATCH DM ──
        print(f"  → Writing back to DM (PATCH /admin/accounts/{acc_id})...")
        patch_body = {
            "access_token": at,
            "token_context": new_token_context,
        }
        if account_id:
            patch_body["account_id"] = account_id

        patch_result = dm.patch_account(acc_id, patch_body)
        if not patch_result.get("ok"):
            print(f"  ❌ PATCH failed: {patch_result}")
            results.append({"email": email, "ok": False, "error": f"patch_failed: {patch_result}"})
            continue

        print(f"  ✅ DM PATCH success")

        # ── Verify ──
        verify = dm.find_account(email)
        if verify:
            v_tc = verify.get("token_context", "?")
            v_at = verify.get("access_token", "")
            at_match = v_at[:20] == at[:20] if v_at and at else False
            print(f"  ✅ Verified: token_context={v_tc}, AT match={at_match}")

        # ── Save session locally ──
        session_file = os.path.join(output_dir, f"{email}.session.json")
        with open(session_file, "w") as f:
            json.dump({
                "email": email,
                "access_token": at,
                "session_cookie": result.get("session_cookie", ""),
                "plan_type": plan_type,
                "token_context": new_token_context,
                "account_id": account_id,
                "scopes": scopes,
                "user": result.get("user", {}),
                "expires": result.get("expires"),
                "dm_id": acc_id,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            }, f, indent=2)
        print(f"  💾 Saved to: {session_file}")

        print(f"\n  ✅ {email} — relogin complete ({token_context} → {new_token_context})")
        results.append({
            "email": email,
            "ok": True,
            "token_context": new_token_context,
            "plan_type": plan_type,
        })

    # Summary
    print(f"\n{'='*60}")
    ok_count = sum(1 for r in results if r["ok"])
    print(f"Relogin summary: {ok_count}/{len(results)} succeeded")
    for r in results:
        status_icon = "✅" if r["ok"] else "❌"
        if r["ok"]:
            print(f"  {status_icon} {r['email']} → token_context={r['token_context']} (plan={r['plan_type']})")
        else:
            print(f"  {status_icon} {r['email']} — {r.get('error', '')}")


# ---------------------------------------------------------------------------
#  oauth-free command — OAuth DM accounts into free CPA (cpa.lsai.uk)
# ---------------------------------------------------------------------------


def cmd_oauth_free(cfg, args):
    proxy = (getattr(args, "proxy", None) or cfg.get("proxy")) or None
    if getattr(args, "proxy", None):
        print(f"🌐 proxy override: {args.proxy.split('@')[-1]}")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]

    cpa_mgmt = CPAMgmt(cfg["cpa_mgmt_base"], cfg["cpa_mgmt_bearer"])
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    # ── Collect existing free CPA emails ──
    print("Fetching free CPA auth files...")
    cpa_files = cpa_mgmt.list_auth_files()
    cpa_emails = set()
    for f in cpa_files:
        e = (f.get("email") or f.get("account") or "").lower()
        if e:
            cpa_emails.add(e)
    print(f"  Free CPA has {len(cpa_emails)} existing auth files")

    # ── Get DM accounts ──
    if args.email:
        acc = dm.find_account(args.email)
        if not acc:
            print(f"❌ Account not found in DM: {args.email}")
            return
        all_accounts = [acc]
    else:
        print("Fetching DM accounts...")
        all_accounts = dm.list_accounts()
        print(f"  DM has {len(all_accounts)} accounts total")

    # ── Filter: category, not already in free CPA ──
    cat_filter = args.category.lower() if args.category else None
    pre_candidates = []
    skipped_cat = 0
    skipped_cpa = 0
    for acc in all_accounts:
        email = (acc.get("email") or "").lower()
        cat = (acc.get("category") or "").strip().lower()
        if cat_filter and cat != cat_filter:
            skipped_cat += 1
            continue
        if email in cpa_emails:
            skipped_cpa += 1
            continue
        pre_candidates.append(acc)

    filters = []
    if skipped_cat:
        filters.append(f"{skipped_cat} category mismatch")
    if skipped_cpa:
        filters.append(f"{skipped_cpa} already in CPA")
    print(f"  Pre-filter: {len(pre_candidates)} candidates"
          + (f" (skipped {', '.join(filters)})" if filters else ""))

    if not pre_candidates:
        print("⏭️  No candidates to process")
        return

    # ── Check deactivated status ──
    print(f"\nChecking deactivated status for {len(pre_candidates)} accounts...")
    candidates = []
    deactivated_count = 0
    check_error_count = 0
    for acc in pre_candidates:
        email = acc.get("email", "")
        result = check_deactivated(email, otp_token)
        if result.get("error"):
            # If check fails, include the account (fail-open)
            check_error_count += 1
            candidates.append(acc)
        elif result.get("deactivated"):
            deactivated_count += 1
        else:
            candidates.append(acc)

    print(f"  Result: {len(candidates)} alive, {deactivated_count} deactivated"
          + (f", {check_error_count} check errors (included)" if check_error_count else ""))

    if not candidates:
        print("⏭️  No non-deactivated candidates found")
        return

    # ── Apply count limit ──
    candidates.sort(key=lambda x: (
        0 if (x.get("status") or "").lower() == "error" else 1,
        int(x.get("id") or 10**9),
    ))
    count = args.count
    if count > 0:
        candidates = candidates[:count]

    print(f"\n🚀 Processing {len(candidates)} accounts for free CPA OAuth...\n")

    # ── OAuth each candidate ──
    results = []
    for i, acc in enumerate(candidates):
        email = acc.get("email", "")
        acc_id = acc.get("id", "?")
        category = acc.get("category", "?")
        tc = acc.get("token_context", "?")

        print(f"{'='*60}")
        print(f"[{i+1}/{len(candidates)}] OAuth-Free: {email}")
        print(f"  id={acc_id}  category={category}  token_context={tc}")
        print(f"{'='*60}")

        # Get OAuth URL from free CPA
        url_resp = cpa_mgmt.get_oauth_url()
        if not url_resp.get("ok"):
            print(f"  ❌ get_oauth_url failed: {url_resp}")
            results.append({"email": email, "ok": False, "error": f"get_oauth_url: {url_resp}"})
            continue

        oauth_url = url_resp.get("url")
        cpa_state = url_resp.get("state")
        if not oauth_url:
            print(f"  ❌ No OAuth URL returned")
            results.append({"email": email, "ok": False, "error": "no_oauth_url"})
            continue

        print(f"  → OAuth URL obtained, completing login...")

        # Complete OAuth login
        code, state, err = oauth_login(oauth_url, email, password, otp_token, proxy)
        if not code:
            print(f"  ❌ OAuth login failed: {err}")
            results.append({"email": email, "ok": False, "error": f"oauth_login: {err}"})
            continue

        print(f"  ✅ OAuth login complete, sending callback...")

        # Send callback to free CPA
        cb_resp = cpa_mgmt.oauth_callback(state or cpa_state, code)
        if not cb_resp.get("ok"):
            print(f"  ❌ Callback failed: {cb_resp}")
            results.append({"email": email, "ok": False, "error": f"callback: {cb_resp}"})
            continue

        print(f"  ✅ OAuth-Free complete for {email}")
        results.append({
            "email": email,
            "ok": True,
            "category": category,
        })

    # Summary
    print(f"\n{'='*60}")
    ok_count = sum(1 for r in results if r["ok"])
    fail_count = len(results) - ok_count
    print(f"OAuth-Free summary: {ok_count} succeeded, {fail_count} failed (of {len(results)} processed)")
    for r in results:
        status_icon = "✅" if r["ok"] else "❌"
        if r["ok"]:
            print(f"  {status_icon} {r['email']} ({r.get('category','?')})")
        else:
            print(f"  {status_icon} {r['email']} — {r.get('error', '')}")


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Codex Toolkit — register + OAuth automation",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    parser.add_argument("-c", "--config", help="config.json path")
    sub = parser.add_subparsers(dest="command")

    # register
    p_reg = sub.add_parser("register", help="Register new ChatGPT accounts")
    p_reg.add_argument("--count", "-n", type=int, default=1, help="number of accounts")
    p_reg.add_argument("--email", "-e", help="specific email to register (overrides random generation; forces count=1)")
    p_reg.add_argument("--domain", "-d", help="specific domain to use (auto-generates prefix); overrides daily rotation")
    p_reg.add_argument("--proxy", help="override config.json proxy for this run (e.g. http://user:pass@host:port)")
    p_reg.add_argument("--rt", action="store_true", help="also get ChatGPT RT via full PKCE OAuth (saved to .chatgpt.json)")

    # oauth
    p_oauth = sub.add_parser("oauth", help="OAuth for existing accounts (team→CPA-B)")
    p_oauth.add_argument("--email", "-e", help="specific email (skip candidate selection)")
    p_oauth.add_argument("--count", "-n", type=int, default=0, help="max candidates (0=all)")
    p_oauth.add_argument("--proxy", help="override config.json proxy for this run")

    # session — full-permission ChatGPT AT
    p_session = sub.add_parser("session", help="Get full-permission ChatGPT session AT (for invite etc.)")
    p_session.add_argument("--email", "-e", help="email to login (default: latest registered)")
    p_session.add_argument("--proxy", help="override config.json proxy for this run")

    # dm-writeback — get team session AT and write back to DM
    p_wb = sub.add_parser("dm-writeback", help="Get team session AT and write back to DM")
    p_wb.add_argument("--email", "-e", help="specific email (skip candidate selection)")
    p_wb.add_argument("--count", "-n", type=int, default=0, help="max candidates (0=all)")
    p_wb.add_argument("--proxy", help="override config.json proxy for this run")

    # relogin — re-login unknown accounts to get free AT
    p_relogin = sub.add_parser("relogin", help="Re-login accounts with token_context=unknown to get free AT")
    p_relogin.add_argument("--email", "-e", help="specific email (skip candidate selection)")
    p_relogin.add_argument("--count", "-n", type=int, default=1, help="number of candidates to process")
    p_relogin.add_argument("--proxy", help="override config.json proxy for this run")

    # oauth-free — OAuth into free CPA for non-deactivated accounts
    p_ofree = sub.add_parser("oauth-free", help="OAuth DM accounts into free CPA (non-deactivated only)")
    p_ofree.add_argument("--email", "-e", help="specific email")
    p_ofree.add_argument("--count", "-n", type=int, default=0, help="max candidates (0=all)")
    p_ofree.add_argument("--category", help="filter by DM category (e.g. enterprise, business, unsubscribed)")
    p_ofree.add_argument("--proxy", help="override config.json proxy for this run")

    args = parser.parse_args()
    setup_logging(args.verbose)

    cfg = load_config(args.config)

    if args.command == "register":
        cmd_register(cfg, args)
    elif args.command == "oauth":
        cmd_oauth(cfg, args)
    elif args.command == "session":
        cmd_session(cfg, args)
    elif args.command == "dm-writeback":
        cmd_dm_writeback(cfg, args)
    elif args.command == "relogin":
        cmd_relogin(cfg, args)
    elif args.command == "oauth-free":
        cmd_oauth_free(cfg, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
