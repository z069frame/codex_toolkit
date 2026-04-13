"""
Codex Toolkit — FastAPI Web Service

Provides REST API + embedded WebUI for account operations:
  - Register, OAuth, Session, DM Writeback, Relogin, OAuth-Free

Tasks run in background threads; status is polled via /api/tasks/{id}.

Usage:
  uvicorn web.app:app --host 0.0.0.0 --port 8000
  # or: python -m web.app
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ── Ensure project root is on sys.path ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import load_config
from core.api import CPAAdmin, CPAMgmt, DataManager, decode_jwt_claims, check_deactivated
from core.chatgpt_session import get_chatgpt_session_at, get_chatgpt_full_tokens
from core.email_gen import generate_email, get_today_domain
from core.openai_auth import register_account, oauth_login, oauth_login_multi

LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
logging.basicConfig(format=LOG_FMT, level=logging.INFO)
logger = logging.getLogger("web")

# ── Config ──
CFG = load_config(str(PROJECT_ROOT / "config.json"))
OUTPUT_DIR = str(PROJECT_ROOT / CFG.get("output_dir", "output"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Auth ──
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", CFG.get("auth_password", "lishuai"))
AUTH_COOKIE = "codex_auth"
AUTH_TOKEN = hashlib.sha256(f"codex_{AUTH_PASSWORD}".encode()).hexdigest()[:32]

# ── FastAPI ──
app = FastAPI(title="Codex Toolkit", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Always allow: login endpoint, static files, index page (has login form)
    if path in ("/", "/api/login") or path.startswith("/static/"):
        return await call_next(request)
    # Check auth cookie
    if request.cookies.get(AUTH_COOKIE) != AUTH_TOKEN:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


# ── In-memory task store ──
tasks: dict[str, dict] = {}

# ── Runtime proxy ──
_PROXY_FILE = str(PROJECT_ROOT / ".runtime_proxy")
_runtime_proxy: str | None = None  # None = use config.json default


def _load_saved_proxy():
    """Load persisted proxy override on startup."""
    global _runtime_proxy
    try:
        if os.path.exists(_PROXY_FILE):
            with open(_PROXY_FILE) as f:
                val = f.read().strip()
            if val:
                _runtime_proxy = val
                logger.info("Loaded saved proxy override: %s",
                            _mask_proxy(val))
    except Exception:
        pass


def _save_proxy(proxy: str | None):
    """Persist proxy override to disk."""
    try:
        if proxy:
            with open(_PROXY_FILE, "w") as f:
                f.write(proxy)
        elif os.path.exists(_PROXY_FILE):
            os.remove(_PROXY_FILE)
    except Exception:
        pass


def _parse_proxy(raw: str) -> str | None:
    """
    Normalize proxy string to a usable URL.

    Accepted formats:
      http://host:port           → as-is
      https://host:port          → as-is
      socks5://host:port         → as-is
      socks5h://host:port        → as-is
      host:port                  → http://host:port
      user:pass@host:port        → http://user:pass@host:port
      http://user:pass@host:port → as-is
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip().rstrip("/")
    if raw.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://")):
        return raw
    # bare host:port or user:pass@host:port
    if ":" in raw:
        return f"http://{raw}"
    return None


def _mask_proxy(proxy: str | None) -> str | None:
    """Hide credentials in proxy URL for display."""
    if not proxy:
        return None
    m = re.match(r'^(https?|socks[45h]*)://([^@]+)@(.+)$', proxy)
    if m:
        return f"{m.group(1)}://***@{m.group(3)}"
    return proxy


def _get_proxy(req_proxy: str | None = None) -> str | None:
    """Resolve proxy: request override > runtime override > config default."""
    if req_proxy:
        return _parse_proxy(req_proxy)
    if _runtime_proxy is not None:
        return _runtime_proxy
    return CFG.get("proxy")


# Load saved proxy on module import
_load_saved_proxy()


# ---------------------------------------------------------------------------
#  Models
# ---------------------------------------------------------------------------

class RegisterReq(BaseModel):
    count: int = 1
    email: Optional[str] = None
    domain: Optional[str] = None
    proxy: Optional[str] = None
    rt: bool = False
    loop: bool = False
    min_sleep: int = 30     # seconds
    max_sleep: int = 180    # seconds


class SingleEmailReq(BaseModel):
    email: Optional[str] = None
    count: int = 0
    proxy: Optional[str] = None


class OAuthFreeReq(BaseModel):
    email: Optional[str] = None
    count: int = 0
    category: Optional[str] = None
    proxy: Optional[str] = None


class ProxyReq(BaseModel):
    proxy: str = ""


class HealthCheckReq(BaseModel):
    dry_run: bool = False


class DeactivationScanReq(BaseModel):
    dry_run: bool = False
    category: Optional[str] = None


class LoginReq(BaseModel):
    password: str


class OAuthMultiReq(BaseModel):
    email: str
    workspace_ids: Optional[list[str]] = None  # None = all workspaces
    proxy: Optional[str] = None


# ---------------------------------------------------------------------------
#  Task helpers
# ---------------------------------------------------------------------------

def _create_task(command: str, params: dict) -> str:
    task_id = uuid.uuid4().hex[:12]
    task = {
        "id": task_id,
        "command": command,
        "params": params,
        "status": "running",
        "logs": [],
        "result": None,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "finished_at": None,
    }
    tasks[task_id] = task
    return task_id


def _log(task_id: str, msg: str):
    if task_id in tasks:
        tasks[task_id]["logs"].append(msg)
    logger.info("[%s] %s", task_id, msg)


def _finish(task_id: str, result: Any, status: str = "done"):
    if task_id in tasks:
        tasks[task_id]["status"] = status
        tasks[task_id]["result"] = result
        tasks[task_id]["finished_at"] = datetime.datetime.utcnow().isoformat() + "Z"


def _is_stopped(task_id: str) -> bool:
    return tasks.get(task_id, {}).get("stop_requested", False)


# ---------------------------------------------------------------------------
#  Shared helpers (reused from main.py logic)
# ---------------------------------------------------------------------------

def _do_cpa_mgmt_oauth(cpa_mgmt: CPAMgmt, email: str, password: str,
                        otp_token: str, proxy: str | None) -> dict:
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
#  Background task runners
# ---------------------------------------------------------------------------

def _register_one(task_id: str, req: RegisterReq, dm, cpa_mgmt,
                  password, otp_token, client_id, redirect_uri, domains,
                  proxy, fixed_email, fixed_domain, idx_label: str) -> dict:
    """Register a single account. Shared by one-shot and loop modes."""
    email = fixed_email or generate_email(domains, domain=fixed_domain)
    _log(task_id, f"{idx_label} Registering {email}")

    reg = register_account(email=email, password=password, otp_token=otp_token,
                           client_id=client_id, redirect_uri=redirect_uri, proxy=proxy)
    if not reg["ok"]:
        _log(task_id, f"❌ {email}: {reg.get('error')}")
        return {"email": email, "ok": False, "error": reg.get("error")}

    phone_required = reg.get("phone_required", False)
    at = reg["access_token"]
    rt = reg["refresh_token"]

    if phone_required:
        _log(task_id, f"⚠️ {email}: phone required, trying session fallback")
        sess = get_chatgpt_session_at(email, password, otp_token, proxy)
        if sess["ok"]:
            at = sess["access_token"]
            _log(task_id, f"✅ {email}: session AT obtained (len={len(at)})")
        else:
            _log(task_id, f"⚠️ {email}: session failed: {sess['error']}")
    else:
        _log(task_id, f"✅ {email}: registered (AT={len(at)}, RT={len(rt)})")

    chatgpt_rt = ""
    if req.rt:
        _log(task_id, f"→ {email}: getting RT via PKCE OAuth")
        rt_res = get_chatgpt_full_tokens(email, password, otp_token, proxy)
        if rt_res["ok"]:
            chatgpt_rt = rt_res["refresh_token"]
            if not at:
                at = rt_res["access_token"]
            _log(task_id, f"✅ {email}: RT obtained (len={len(chatgpt_rt)})")
        else:
            _log(task_id, f"⚠️ {email}: RT failed: {rt_res['error']}")

    # Save file
    token_file = os.path.join(OUTPUT_DIR, f"{email}.json")
    with open(token_file, "w") as f:
        json.dump({"email": email, "password": password, "access_token": at,
                    "refresh_token": rt, "chatgpt_refresh_token": chatgpt_rt,
                    "phone_required": phone_required,
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z"}, f, indent=2)

    # DM
    if at:
        claims = decode_jwt_claims(at)
        dm_res = dm.create_account(email, password, at, claims.get("sub", ""), token_context="free")
    else:
        dm_res = dm.create_account(email, password, "", "", token_context="unknown")
    dm_ok = dm_res.get("ok", False)
    _log(task_id, f"{'✅' if dm_ok else '⚠️'} {email}: DM {'ok' if dm_ok else 'failed'}")

    # CPA OAuth
    cpa_ok = False
    if at:
        cpa_res = _do_cpa_mgmt_oauth(cpa_mgmt, email, password, otp_token, proxy)
        cpa_ok = cpa_res.get("ok", False)
        _log(task_id, f"{'✅' if cpa_ok else '⚠️'} {email}: CPA {'ok' if cpa_ok else 'failed'}")

    return {"email": email, "ok": True, "phone_required": phone_required,
            "has_at": bool(at), "dm_ok": dm_ok, "cpa_ok": cpa_ok}


def _run_register(task_id: str, req: RegisterReq):
    import random

    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    client_id = cfg["oauth_client_id"]
    redirect_uri = cfg["oauth_redirect_uri"]
    domains = cfg["domains"]

    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    cpa_mgmt = CPAMgmt(cfg["cpa_mgmt_base"], cfg["cpa_mgmt_bearer"])

    fixed_email = (req.email or "").strip() or None
    fixed_domain = (req.domain or "").strip().lstrip("@") or None

    results = []

    if req.loop:
        # ── Loop mode: register → random sleep → check stop → repeat ──
        min_s = max(1, int(req.min_sleep or 30))
        max_s = max(min_s, int(req.max_sleep or 180))
        _log(task_id, f"🔁 Loop mode ON (sleep {min_s}-{max_s}s between accounts)")

        i = 0
        while not _is_stopped(task_id):
            i += 1
            r = _register_one(task_id, req, dm, cpa_mgmt, password, otp_token,
                              client_id, redirect_uri, domains, proxy,
                              None, fixed_domain, f"[loop #{i}]")
            results.append(r)

            if _is_stopped(task_id):
                _log(task_id, "🛑 Stop requested — exiting loop")
                break

            sleep_s = random.randint(min_s, max_s)
            _log(task_id, f"😴 Sleeping {sleep_s}s before next account...")
            # Sleep in 1s chunks so stop is responsive
            for _ in range(sleep_s):
                if _is_stopped(task_id):
                    _log(task_id, "🛑 Stop requested during sleep")
                    break
                import time as _time
                _time.sleep(1)

        ok_count = sum(1 for r in results if r["ok"])
        _log(task_id, f"Loop ended: {ok_count}/{len(results)} registered over {i} iterations")
        _finish(task_id, results, "stopped" if _is_stopped(task_id) else "done")
        return

    # ── One-shot mode ──
    count = 1 if fixed_email else req.count
    for i in range(count):
        if _is_stopped(task_id):
            _log(task_id, "🛑 Stop requested")
            break
        r = _register_one(task_id, req, dm, cpa_mgmt, password, otp_token,
                          client_id, redirect_uri, domains, proxy,
                          fixed_email, fixed_domain, f"[{i+1}/{count}]")
        results.append(r)

    ok_count = sum(1 for r in results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(results)} registered")
    _finish(task_id, results, "stopped" if _is_stopped(task_id) else "done")


def _run_writeback(task_id: str, req: SingleEmailReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    if req.email:
        acc = dm.find_account(req.email)
        if not acc:
            _log(task_id, f"❌ Not found in DM: {req.email}")
            _finish(task_id, {"ok": False, "error": "not_found"}, "error")
            return
        candidates = [acc]
    else:
        candidates = dm.pick_writeback_candidates(req.count)
        if not candidates:
            _log(task_id, "⏭️ No writeback candidates")
            _finish(task_id, [], "done")
            return

    _log(task_id, f"Processing {len(candidates)} candidates")
    results = []
    for i, cand in enumerate(candidates):
        email = cand.get("email", "")
        acc_id = cand.get("id")
        category = cand.get("category", "?")
        _log(task_id, f"[{i+1}/{len(candidates)}] {email} (id={acc_id}, cat={category})")

        result = get_chatgpt_session_at(email, password, otp_token, proxy)
        if not result["ok"]:
            _log(task_id, f"❌ {email}: {result['error']}")
            results.append({"email": email, "ok": False, "error": result["error"]})
            continue

        at = result["access_token"]
        claims = decode_jwt_claims(at)
        auth_info = claims.get("https://api.openai.com/auth", {})
        plan_type = auth_info.get("chatgpt_plan_type", "")
        account_id = auth_info.get("chatgpt_account_id", "")
        new_tc = "team" if plan_type in ("team", "enterprise", "business") else "free"

        _log(task_id, f"✅ {email}: AT obtained, plan={plan_type}, tc→{new_tc}")

        patch_body = {"access_token": at, "token_context": new_tc}
        if account_id:
            patch_body["account_id"] = account_id
        patch_res = dm.patch_account(acc_id, patch_body)
        if not patch_res.get("ok"):
            _log(task_id, f"❌ {email}: PATCH failed")
            results.append({"email": email, "ok": False, "error": "patch_failed"})
            continue

        # Save session file
        session_file = os.path.join(OUTPUT_DIR, f"{email}.session.json")
        with open(session_file, "w") as f:
            json.dump({"email": email, "access_token": at,
                        "session_cookie": result.get("session_cookie", ""),
                        "plan_type": plan_type, "token_context": new_tc,
                        "account_id": account_id,
                        "created_at": datetime.datetime.utcnow().isoformat() + "Z"}, f, indent=2)

        _log(task_id, f"✅ {email}: writeback done ({new_tc})")
        results.append({"email": email, "ok": True, "token_context": new_tc, "plan_type": plan_type})

    ok_count = sum(1 for r in results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(results)} succeeded")
    _finish(task_id, results)


def _run_session(task_id: str, req: SingleEmailReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]

    email = req.email
    if not email:
        _log(task_id, "❌ email is required")
        _finish(task_id, {"ok": False, "error": "email_required"}, "error")
        return

    _log(task_id, f"Getting session for {email}")
    result = get_chatgpt_session_at(email, password, otp_token, proxy)

    if not result["ok"]:
        _log(task_id, f"❌ {result['error']}")
        _finish(task_id, {"ok": False, "error": result["error"]}, "error")
        return

    at = result["access_token"]
    session_cookie = result.get("session_cookie", "")
    user = result.get("user", {})
    expires = result.get("expires", "")
    claims = decode_jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth", {})
    plan_type = auth_info.get("chatgpt_plan_type", "")
    account_id = auth_info.get("chatgpt_account_id", "")

    session_file = os.path.join(OUTPUT_DIR, f"{email}.session.json")
    with open(session_file, "w") as f:
        json.dump({"email": email, "access_token": at,
                    "session_cookie": session_cookie,
                    "plan_type": plan_type,
                    "account_id": account_id,
                    "user": user,
                    "expires": expires,
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z"}, f, indent=2)

    _log(task_id, f"✅ Session obtained: plan={plan_type}, AT len={len(at)}, cookie len={len(session_cookie)}")
    _finish(task_id, {
        "ok": True,
        "email": email,
        "access_token": at,
        "session_cookie": session_cookie,
        "plan_type": plan_type,
        "account_id": account_id,
        "user": user,
        "expires": expires,
    })


def _run_relogin(task_id: str, req: SingleEmailReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    if req.email:
        acc = dm.find_account(req.email)
        if not acc:
            _log(task_id, f"❌ Not found: {req.email}")
            _finish(task_id, {"ok": False, "error": "not_found"}, "error")
            return
        candidates = [acc]
    else:
        candidates = dm.pick_relogin_candidates(req.count or 1)
        if not candidates:
            _log(task_id, "⏭️ No relogin candidates")
            _finish(task_id, [], "done")
            return

    results = []
    for i, cand in enumerate(candidates):
        email = cand.get("email", "")
        acc_id = cand.get("id")
        _log(task_id, f"[{i+1}/{len(candidates)}] {email}")

        result = get_chatgpt_session_at(email, password, otp_token, proxy)
        if not result["ok"]:
            _log(task_id, f"❌ {email}: {result['error']}")
            results.append({"email": email, "ok": False, "error": result["error"]})
            continue

        at = result["access_token"]
        claims = decode_jwt_claims(at)
        account_id = claims.get("sub", "")

        patch_res = dm.patch_account(acc_id, {"access_token": at, "account_id": account_id,
                                               "token_context": "free"})
        if patch_res.get("ok"):
            _log(task_id, f"✅ {email}: relogin done, DM patched")
            results.append({"email": email, "ok": True})
        else:
            _log(task_id, f"⚠️ {email}: AT ok but DM patch failed")
            results.append({"email": email, "ok": False, "error": "dm_patch_failed"})

    ok_count = sum(1 for r in results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(results)} succeeded")
    _finish(task_id, results)


def _run_oauth(task_id: str, req: SingleEmailReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    cpa_admin = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])

    # Login CPA admin first
    if not cpa_admin.login():
        _log(task_id, "❌ CPA admin login failed")
        _finish(task_id, {"ok": False, "error": "cpa_admin_login_failed"}, "error")
        return

    if req.email:
        acc = dm.find_account(req.email)
        if not acc:
            _log(task_id, f"❌ Not found: {req.email}")
            _finish(task_id, {"ok": False, "error": "not_found"}, "error")
            return
        candidates = [acc]
    else:
        candidates = dm.pick_oauth_candidates(cpa_admin, req.count)
        if not candidates:
            _log(task_id, "⏭️ No OAuth candidates")
            _finish(task_id, [], "done")
            return

    _log(task_id, f"Processing {len(candidates)} candidates")
    results = []
    for i, cand in enumerate(candidates):
        email = cand.get("email", "")
        acc_id = cand.get("id", "?")
        category = cand.get("category", "?")
        _log(task_id, f"[{i+1}/{len(candidates)}] OAuth: {email} (id={acc_id}, cat={category})")

        # Start OAuth via CPA admin
        start = cpa_admin.start_oauth()
        if not start.get("ok"):
            _log(task_id, f"❌ {email}: CPA start_oauth failed: {start}")
            results.append({"email": email, "ok": False, "error": f"start_oauth: {start}"})
            continue

        oauth_url = start.get("url")
        cpa_state = start.get("state")
        if not oauth_url:
            _log(task_id, f"❌ {email}: No OAuth URL returned")
            results.append({"email": email, "ok": False, "error": "no_oauth_url"})
            continue

        # Complete OAuth login
        code, state, err = oauth_login(oauth_url, email, password, otp_token, proxy)
        if not code:
            _log(task_id, f"❌ {email}: OAuth login failed: {err}")
            results.append({"email": email, "ok": False, "error": f"oauth_login: {err}"})
            continue

        # Send callback to CPA
        cb_resp = cpa_admin.oauth_callback(state or cpa_state, code)
        if not cb_resp.get("ok"):
            _log(task_id, f"❌ {email}: Callback failed: {cb_resp}")
            results.append({"email": email, "ok": False, "error": f"callback: {cb_resp}"})
            continue

        # Verify auth file and set priority
        auth = cpa_admin.find_auth_by_email(email)
        verified = False
        if auth:
            auth_id = auth.get("id")
            plan = auth.get("plan_type", "?")
            _log(task_id, f"✅ {email}: verified auth_id={auth_id}, plan={plan}")
            cpa_admin.set_priority(auth_id, 100)
            verified = True
        else:
            _log(task_id, f"⚠️ {email}: auth file not found in CPA (may take a moment)")

        _log(task_id, f"✅ {email}: OAuth complete")
        results.append({"email": email, "ok": True, "category": category, "verified": verified})

    ok_count = sum(1 for r in results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(results)} succeeded")
    _finish(task_id, results)


def _run_oauth_multi(task_id: str, req: OAuthMultiReq):
    """
    OAuth all workspaces of a single account into CPAB.
    Uses one login session to iterate through every workspace the account belongs to.
    """
    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    cpa_admin = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])

    if not cpa_admin.login():
        _log(task_id, "❌ CPA admin login failed")
        _finish(task_id, {"ok": False, "error": "cpa_admin_login_failed"}, "error")
        return

    email = req.email.strip()
    if not email:
        _log(task_id, "❌ email is required")
        _finish(task_id, {"ok": False, "error": "email_required"}, "error")
        return

    _log(task_id, f"OAuth ALL workspaces for: {email}")
    if req.workspace_ids:
        _log(task_id, f"Filter: {len(req.workspace_ids)} workspace(s) {req.workspace_ids}")

    # start_oauth_fn returns a fresh CPAB OAuth URL+state per iteration
    def _start():
        return cpa_admin.start_oauth()

    multi = oauth_login_multi(
        start_oauth_fn=_start,
        email=email,
        password=password,
        otp_token=otp_token,
        proxy=proxy,
        workspace_filter=req.workspace_ids,
        log_fn=lambda m: _log(task_id, m),
    )

    if not multi.get("ok") and not multi.get("results"):
        _log(task_id, f"❌ fatal: {multi.get('error')}")
        _finish(task_id, multi, "error")
        return

    workspaces = multi.get("workspaces", [])
    results = multi.get("results", [])

    _log(task_id, f"Login ok, {len(workspaces)} workspaces, {len(results)} OAuth attempts")

    # Process each successful code: send to CPAB callback + verify + set priority
    final_results = []
    for r in results:
        ws_id = r.get("workspace_id", "?")
        ws_name = r.get("workspace_name", "?")
        ws_kind = r.get("workspace_kind", "?")
        tag = f"{ws_name} ({ws_kind})"

        if not r.get("ok") or not r.get("code"):
            _log(task_id, f"  ⏭️ {tag}: skipped — {r.get('error', 'no code')}")
            final_results.append({
                "workspace_id": ws_id, "workspace_name": ws_name, "workspace_kind": ws_kind,
                "ok": False, "error": r.get("error", "no_code"),
            })
            continue

        code = r["code"]
        state = r.get("state", "")
        cb_resp = cpa_admin.oauth_callback(state, code)
        if not cb_resp.get("ok"):
            _log(task_id, f"  ❌ {tag}: callback failed: {cb_resp}")
            final_results.append({
                "workspace_id": ws_id, "workspace_name": ws_name, "workspace_kind": ws_kind,
                "ok": False, "error": f"callback: {cb_resp}",
            })
            continue

        _log(task_id, f"  ✅ {tag}: callback ok")

        # Verify by searching CPAB for a team auth on this specific workspace
        # find_auth_by_email picks best codex auth; may miss per-workspace details
        # but still useful to set priority
        auth = cpa_admin.find_auth_by_email(email)
        if auth:
            auth_id = auth.get("id")
            cpa_admin.set_priority(auth_id, 100)
            _log(task_id, f"     auth_id={auth_id} priority set")

        final_results.append({
            "workspace_id": ws_id, "workspace_name": ws_name, "workspace_kind": ws_kind,
            "ok": True,
        })

    ok_count = sum(1 for r in final_results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(final_results)} workspaces OAuth'd")
    _finish(task_id, {
        "ok": True,
        "email": email,
        "workspaces": workspaces,
        "results": final_results,
    })


def _run_oauth_free(task_id: str, req: OAuthFreeReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy)
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    cpa_mgmt = CPAMgmt(cfg["cpa_mgmt_base"], cfg["cpa_mgmt_bearer"])
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    # Collect existing free CPA emails
    _log(task_id, "Fetching free CPA auth files...")
    cpa_files = cpa_mgmt.list_auth_files()
    cpa_emails = set()
    for f in cpa_files:
        e = (f.get("email") or f.get("account") or "").lower()
        if e:
            cpa_emails.add(e)
    _log(task_id, f"Free CPA has {len(cpa_emails)} existing auth files")

    # Get DM accounts
    if req.email:
        acc = dm.find_account(req.email)
        if not acc:
            _log(task_id, f"❌ Not found: {req.email}")
            _finish(task_id, {"ok": False, "error": "not_found"}, "error")
            return
        all_accounts = [acc]
    else:
        all_accounts = dm.list_accounts()
        _log(task_id, f"DM has {len(all_accounts)} accounts total")

    # Filter: category, not already in free CPA
    cat_filter = req.category.lower() if req.category else None
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
    _log(task_id, f"Pre-filter: {len(pre_candidates)} candidates"
         + (f" (skipped {', '.join(filters)})" if filters else ""))

    if not pre_candidates:
        _log(task_id, "⏭️ No candidates to process")
        _finish(task_id, [], "done")
        return

    # Check deactivated status
    _log(task_id, f"Checking deactivated status for {len(pre_candidates)} accounts...")
    candidates = []
    deactivated_count = 0
    for acc in pre_candidates:
        email = acc.get("email", "")
        result = check_deactivated(email, otp_token)
        if result.get("deactivated"):
            deactivated_count += 1
        else:
            candidates.append(acc)

    _log(task_id, f"Alive: {len(candidates)}, deactivated: {deactivated_count}")

    if not candidates:
        _log(task_id, "⏭️ No non-deactivated candidates found")
        _finish(task_id, [], "done")
        return

    # Sort and limit
    candidates.sort(key=lambda x: (
        0 if (x.get("status") or "").lower() == "error" else 1,
        int(x.get("id") or 10**9),
    ))
    count = req.count
    if count > 0:
        candidates = candidates[:count]

    _log(task_id, f"Processing {len(candidates)} accounts for free CPA OAuth")
    results = []
    for i, acc in enumerate(candidates):
        email = acc.get("email", "")
        category = acc.get("category", "?")
        _log(task_id, f"[{i+1}/{len(candidates)}] OAuth-Free: {email} (cat={category})")

        cpa_res = _do_cpa_mgmt_oauth(cpa_mgmt, email, password, otp_token, proxy)
        ok = cpa_res.get("ok", False)
        _log(task_id, f"{'✅' if ok else '❌'} {email}: {'done' if ok else cpa_res.get('error','')}")
        results.append({"email": email, "ok": ok, "category": category,
                         "error": cpa_res.get("error") if not ok else None})

    ok_count = sum(1 for r in results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(results)} succeeded")
    _finish(task_id, results)


def _run_health_check(task_id: str, req: HealthCheckReq):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    cfg = CFG
    otp_token = cfg["otp_token"]
    dry_run = req.dry_run
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    cpa_admin = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])

    if dry_run:
        _log(task_id, "⚠️ DRY-RUN mode — no deletions will be performed")

    # 1) CPAB login
    if not cpa_admin.login():
        _log(task_id, "❌ CPA admin login failed")
        _finish(task_id, {"ok": False, "error": "cpa_admin_login_failed"}, "error")
        return

    # 2) List & dedup
    _log(task_id, "Fetching CPAB auth-files...")
    files = cpa_admin.list_auth_files()
    auths = cpa_admin.extract_codex_auths(files)
    if not auths:
        _log(task_id, "⏭️ No codex auth entries found")
        _finish(task_id, {"ok": True, "total": 0}, "done")
        return
    _log(task_id, f"Found {len(auths)} codex auth entries (deduplicated)")

    # 3) Verify each token via DM
    _log(task_id, "Verifying tokens via DM...")

    def _check_one(auth):
        r = dm.verify_token(auth["access_token"])
        return {
            "email": auth["email"],
            "auth_id": auth["auth_id"],
            "plan_type": auth.get("plan_type", "unknown"),
            "ok": r.get("ok", False),
            "reason": r.get("reason", "unknown"),
            "http_status": r.get("status", 0),
        }

    results = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_check_one, a): a for a in auths}
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r["auth_id"], reverse=True)

    passed = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    fatal = [r for r in failed if r["reason"] in ("unauthorized", "account_deactivated", "token_invalidated") or r["http_status"] == 401]

    _log(task_id, f"Total: {len(results)} | Pass: {len(passed)} | Fail: {len(failed)} | Fatal: {len(fatal)}")

    # 4) Handle expired (unauthorized/401)
    expired = [r for r in results if r["reason"] == "unauthorized" or r["http_status"] == 401]
    expired_emails = {r["email"] for r in expired}

    deactivated_deleted = []
    expired_deleted = []

    if expired_emails:
        raw_auths = cpa_admin.collect_auth_ids_for_emails(expired_emails, files)
        _log(task_id, f"Checking deactivation for {len(expired_emails)} expired account(s)...")

        for email in sorted(expired_emails):
            auth_ids = [a["auth_id"] for a in raw_auths if a["email"] == email]
            is_deactivated = check_deactivated(email, otp_token).get("deactivated")

            if is_deactivated:
                label = "DEACTIVATED"
            elif is_deactivated is False:
                label = "EXPIRED"
            else:
                _log(task_id, f"  ⏭️ {email}: deactivation check unavailable, skipping")
                continue

            if dry_run:
                _log(task_id, f"  🔍 {label} {email} — would delete {len(auth_ids)} auth(s) {auth_ids}")
                bucket = deactivated_deleted if is_deactivated else expired_deleted
                for aid in auth_ids:
                    bucket.append({"email": email, "auth_id": aid, "dry_run": True})
            else:
                for aid in auth_ids:
                    ok = cpa_admin.delete_auth_file(aid)
                    bucket = deactivated_deleted if is_deactivated else expired_deleted
                    bucket.append({"email": email, "auth_id": aid, "deleted": ok})
                    icon = "✅" if ok else "❌"
                    _log(task_id, f"  {icon} {label} {email} auth_id={aid} {'deleted' if ok else 'delete failed'}")

    # 5) Log healthy
    for r in passed:
        plan_tag = f" [{r['plan_type']}]" if r.get("plan_type") != "unknown" else ""
        _log(task_id, f"  ✅ {r['email']}{plan_tag}")

    # 6) Log other failures
    other_failed = [r for r in failed if r["email"] not in expired_emails]
    for r in other_failed:
        _log(task_id, f"  ⚠️ {r['email']} — {r['reason']} (HTTP {r['http_status']})")

    total_deleted = len(deactivated_deleted) + len(expired_deleted)
    _log(task_id, f"Summary: {len(passed)} healthy, {len(failed)} failed, "
         f"{len(deactivated_deleted)} deactivated deleted, {len(expired_deleted)} expired deleted"
         + (" (dry-run)" if dry_run else ""))

    _finish(task_id, {
        "ok": True,
        "total": len(results),
        "passed": len(passed),
        "failed": len(failed),
        "deactivated_deleted": deactivated_deleted,
        "expired_deleted": expired_deleted,
        "other_failed": [{"email": r["email"], "reason": r["reason"]} for r in other_failed],
    })


def _run_deactivation_scan(task_id: str, req: DeactivationScanReq):
    """
    Scan all DM accounts for deactivation emails.
    For deactivated accounts: delete all auth files from CPAB + disable in DM.
    """
    cfg = CFG
    otp_token = cfg["otp_token"]
    dry_run = req.dry_run
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    cpa_admin = CPAAdmin(cfg["cpa_admin_base"], cfg["cpa_admin_user"], cfg["cpa_admin_password"])

    if dry_run:
        _log(task_id, "⚠️ DRY-RUN mode — no deletions or disables will be performed")

    # 1) CPAB login
    if not cpa_admin.login():
        _log(task_id, "❌ CPA admin login failed")
        _finish(task_id, {"ok": False, "error": "cpa_admin_login_failed"}, "error")
        return

    # 2) List DM accounts
    _log(task_id, "Fetching DM accounts...")
    all_accounts = dm.list_accounts(include_disabled=False)
    if not all_accounts:
        _log(task_id, "⏭️ No accounts found in DM")
        _finish(task_id, {"ok": True, "total": 0}, "done")
        return

    # Filter by category if specified
    cat_filter = req.category.lower().strip() if req.category else None
    if cat_filter:
        all_accounts = [a for a in all_accounts
                        if (a.get("category") or "").lower().strip() == cat_filter]
        _log(task_id, f"Filtered to {len(all_accounts)} accounts (category={cat_filter})")
    else:
        _log(task_id, f"Scanning {len(all_accounts)} active DM accounts")

    # 3) Get CPAB auth files once for batch lookups
    _log(task_id, "Fetching CPAB auth-files...")
    cpab_files = cpa_admin.list_auth_files()

    # 4) Scan each account for deactivation emails
    deactivated = []
    checked = 0
    errors = 0
    for i, acc in enumerate(all_accounts):
        email = (acc.get("email") or "").strip().lower()
        if not email or "@" not in email:
            continue

        checked += 1
        if checked % 20 == 0:
            _log(task_id, f"  Progress: {checked}/{len(all_accounts)} checked, "
                 f"{len(deactivated)} deactivated found...")

        result = check_deactivated(email, otp_token)
        if result.get("error"):
            errors += 1
            continue

        if result.get("deactivated"):
            match_count = result.get("matched_count", 0)
            first_match = (result.get("matches") or [{}])[0]
            subject = first_match.get("subject", "")[:60]
            _log(task_id, f"  🔴 {email}: DEACTIVATED ({match_count} match(es)) — {subject}")
            deactivated.append({
                "email": email,
                "acc_id": acc.get("id"),
                "category": acc.get("category", ""),
                "matches": result.get("matches", []),
            })

    _log(task_id, f"Scan complete: {checked} checked, {len(deactivated)} deactivated, {errors} errors")

    if not deactivated:
        _log(task_id, "✅ No deactivated accounts found")
        _finish(task_id, {"ok": True, "checked": checked, "deactivated": 0, "actions": []}, "done")
        return

    # 5) Process deactivated accounts
    _log(task_id, f"Processing {len(deactivated)} deactivated accounts...")
    actions = []
    deactivated_emails = {d["email"] for d in deactivated}
    cpab_auths = cpa_admin.collect_auth_ids_for_emails(deactivated_emails, cpab_files)

    for entry in deactivated:
        email = entry["email"]
        acc_id = entry["acc_id"]
        auth_ids = [a["auth_id"] for a in cpab_auths if a["email"] == email]
        action = {"email": email, "acc_id": acc_id, "category": entry["category"],
                  "cpab_deleted": [], "dm_disabled": False}

        # Delete from CPAB
        if auth_ids:
            if dry_run:
                _log(task_id, f"  🔍 {email}: would delete {len(auth_ids)} CPAB auth(s) {auth_ids}")
                action["cpab_deleted"] = [{"auth_id": aid, "dry_run": True} for aid in auth_ids]
            else:
                for aid in auth_ids:
                    ok = cpa_admin.delete_auth_file(aid)
                    action["cpab_deleted"].append({"auth_id": aid, "deleted": ok})
                    icon = "✅" if ok else "❌"
                    _log(task_id, f"  {icon} {email}: CPAB auth_id={aid} {'deleted' if ok else 'delete failed'}")
        else:
            _log(task_id, f"  ⏭️ {email}: no CPAB auth files found")

        # Disable in DM
        if acc_id:
            if dry_run:
                _log(task_id, f"  🔍 {email}: would disable in DM (id={acc_id})")
                action["dm_disabled"] = "dry_run"
            else:
                patch_res = dm.patch_account(acc_id, {"status": "disabled"})
                ok = patch_res.get("ok", False)
                action["dm_disabled"] = ok
                icon = "✅" if ok else "❌"
                _log(task_id, f"  {icon} {email}: DM {'disabled' if ok else 'disable failed'} (id={acc_id})")

        actions.append(action)

    cpab_count = sum(len(a["cpab_deleted"]) for a in actions)
    dm_count = sum(1 for a in actions if a["dm_disabled"] is True)
    _log(task_id, f"Summary: {len(deactivated)} deactivated, "
         f"{cpab_count} CPAB auths processed, {dm_count} DM disabled"
         + (" (dry-run)" if dry_run else ""))

    _finish(task_id, {
        "ok": True,
        "checked": checked,
        "deactivated": len(deactivated),
        "errors": errors,
        "actions": actions,
    })


# ---------------------------------------------------------------------------
#  API Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def index():
    """Serve index.html with config injected as JS variable."""
    html_path = Path(__file__).parent / "static" / "index.html"
    html = html_path.read_text(encoding="utf-8")
    domains = CFG.get("domains", [])
    today_domain = get_today_domain(domains) if domains else ""
    inject = json.dumps({"domains": domains, "today_domain": today_domain})
    html = html.replace("/*__SERVER_CONFIG__*/", f"window.__CFG__={inject};", 1)
    return HTMLResponse(content=html)


@app.post("/api/login")
async def api_login(req: LoginReq):
    if req.password != AUTH_PASSWORD:
        raise HTTPException(401, "Wrong password")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(AUTH_COOKIE, AUTH_TOKEN, httponly=True,
                    max_age=86400 * 30, samesite="lax")
    return resp


@app.get("/api/config")
async def get_config():
    """Return safe subset of config for UI display."""
    domains = CFG.get("domains", [])
    today_domain = get_today_domain(domains) if domains else None
    return {
        "domains": domains,
        "today_domain": today_domain,
        "dm_base": CFG.get("dm_base"),
        "cpa_mgmt_base": CFG.get("cpa_mgmt_base"),
    }


# ── Proxy management ──

@app.get("/api/proxy")
async def get_proxy():
    return {
        "active": _mask_proxy(_get_proxy()),
        "active_raw": _get_proxy(),
        "config_default": _mask_proxy(CFG.get("proxy")),
        "runtime_override": _mask_proxy(_runtime_proxy),
        "has_override": _runtime_proxy is not None,
    }


@app.put("/api/proxy")
async def set_proxy(req: ProxyReq):
    global _runtime_proxy
    parsed = _parse_proxy(req.proxy)
    if req.proxy.strip() and not parsed:
        raise HTTPException(400, f"Invalid proxy format: {req.proxy}")
    _runtime_proxy = parsed
    _save_proxy(parsed)
    return {
        "ok": True,
        "active": _mask_proxy(_get_proxy()),
        "runtime_override": _mask_proxy(_runtime_proxy),
    }


@app.delete("/api/proxy")
async def clear_proxy():
    global _runtime_proxy
    _runtime_proxy = None
    _save_proxy(None)
    return {
        "ok": True,
        "active": _mask_proxy(_get_proxy()),
        "runtime_override": None,
    }


# ── Accounts ──

@app.get("/api/accounts")
async def list_accounts():
    """List DM accounts (recent 100)."""
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    try:
        accounts = dm.list_accounts()
        return {"ok": True, "accounts": accounts[:100], "total": len(accounts)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/accounts/{email}")
async def get_account(email: str):
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    acc = dm.find_account(email)
    if not acc:
        raise HTTPException(404, f"Account not found: {email}")
    return acc


# ── Task endpoints ──

@app.post("/api/register")
async def api_register(req: RegisterReq):
    task_id = _create_task("register", req.model_dump())
    threading.Thread(target=_run_register, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/writeback")
async def api_writeback(req: SingleEmailReq):
    task_id = _create_task("writeback", req.model_dump())
    threading.Thread(target=_run_writeback, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/session")
async def api_session(req: SingleEmailReq):
    task_id = _create_task("session", req.model_dump())
    threading.Thread(target=_run_session, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/relogin")
async def api_relogin(req: SingleEmailReq):
    task_id = _create_task("relogin", req.model_dump())
    threading.Thread(target=_run_relogin, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/oauth")
async def api_oauth(req: SingleEmailReq):
    task_id = _create_task("oauth", req.model_dump())
    threading.Thread(target=_run_oauth, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/oauth-free")
async def api_oauth_free(req: OAuthFreeReq):
    task_id = _create_task("oauth-free", req.model_dump())
    threading.Thread(target=_run_oauth_free, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/oauth-multi")
async def api_oauth_multi(req: OAuthMultiReq):
    task_id = _create_task("oauth-multi", req.model_dump())
    threading.Thread(target=_run_oauth_multi, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/health-check")
async def api_health_check(req: HealthCheckReq):
    task_id = _create_task("health-check", req.model_dump())
    threading.Thread(target=_run_health_check, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/deactivation-scan")
async def api_deactivation_scan(req: DeactivationScanReq):
    task_id = _create_task("deactivation-scan", req.model_dump())
    threading.Thread(target=_run_deactivation_scan, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    return task


@app.post("/api/tasks/{task_id}/stop")
async def stop_task(task_id: str):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    task["stop_requested"] = True
    return {"ok": True, "task_id": task_id}


@app.get("/api/tasks")
async def list_tasks():
    """List recent tasks (newest first)."""
    sorted_tasks = sorted(tasks.values(), key=lambda t: t["created_at"], reverse=True)
    return [
        {"id": t["id"], "command": t["command"], "status": t["status"],
         "created_at": t["created_at"], "finished_at": t["finished_at"],
         "log_count": len(t["logs"])}
        for t in sorted_tasks[:50]
    ]


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
