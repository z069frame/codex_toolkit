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
    # Always allow: login, static, index (has login form),
    # and ACME HTTP-01 challenge path (for Let's Encrypt cert issuance)
    if (path in ("/", "/api/login")
        or path.startswith("/static/")
        or path.startswith("/.well-known/")):
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
    """Load persisted proxy override on startup.

    Priority: RUNTIME_PROXY env var (survives redeploys on Railway) >
    on-disk .runtime_proxy file (per-instance override from Web UI).
    """
    global _runtime_proxy
    # 1) Env var (Railway-safe: set via `railway variables`)
    env_val = os.environ.get("RUNTIME_PROXY", "").strip()
    if env_val:
        _runtime_proxy = env_val
        logger.info("Loaded proxy from RUNTIME_PROXY env: %s",
                    _mask_proxy(env_val))
        return
    # 2) On-disk file (set via PUT /api/proxy; wiped on Railway redeploy)
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


# Per-task proxy overrides: {"register": "socks5://...", "session": "DIRECT"}
_task_proxies: dict[str, str] = {}
_DIRECT = "DIRECT"  # sentinel: explicitly no proxy


def _get_proxy(req_proxy: str | None = None, command: str | None = None) -> str | None:
    """Resolve proxy: request > task-specific > runtime override > config default.
    "DIRECT" or "none" at any level = explicitly no proxy."""
    # 1) Per-request override
    if req_proxy:
        if req_proxy.lower() in ("none", "direct"):
            return None
        return _parse_proxy(req_proxy)
    # 2) Per-task override
    if command and command in _task_proxies:
        val = _task_proxies[command]
        if val == _DIRECT:
            return None
        return val
    # 3) Runtime override
    if _runtime_proxy is not None:
        if _runtime_proxy == _DIRECT:
            return None
        return _runtime_proxy
    # 4) Config default
    return CFG.get("proxy")


# Load saved proxy on module import
_load_saved_proxy()


@app.on_event("startup")
async def _auto_start_tasks():
    """Auto-start background tasks from env vars after server boot.

    Set on Railway via:
      railway variables --set AUTO_REGISTER_LOOP=1
      railway variables --set AUTO_REGISTER_DOMAIN=aitech.email    # optional
      railway variables --set AUTO_REGISTER_MIN_SLEEP=300          # optional
      railway variables --set AUTO_REGISTER_MAX_SLEEP=360          # optional

    Useful because Railway redeploys reset in-memory task state — without
    auto-start every redeploy silently stops the register loop.
    """
    flag = os.environ.get("AUTO_REGISTER_LOOP", "").strip().lower()
    if flag not in ("1", "true", "yes", "on"):
        return
    try:
        domain = os.environ.get("AUTO_REGISTER_DOMAIN", "aitech.email").strip() or None
        min_s = int(os.environ.get("AUTO_REGISTER_MIN_SLEEP", "300"))
        max_s = int(os.environ.get("AUTO_REGISTER_MAX_SLEEP", "360"))
        req = RegisterReq(loop=True, domain=domain,
                          min_sleep=min_s, max_sleep=max_s)
        task_id = _create_task("register", req.model_dump())
        threading.Thread(target=_run_register, args=(task_id, req),
                         daemon=True).start()
        logger.info("[auto-start] register loop started task=%s "
                    "domain=%s sleep=%d-%ds", task_id, domain, min_s, max_s)
    except Exception as e:
        logger.exception("[auto-start] register loop failed to start: %s", e)


def _probe_egress_ip(proxy: str | None, timeout: int = 10) -> str:
    """Get the outbound IP seen by the internet through `proxy`.

    Used at the top of each register/session cycle to verify that
    ProxySeller's residential rotation is actually giving us a fresh IP.
    Never raises — returns a short diagnostic string on failure.
    """
    try:
        from curl_cffi import requests as _cffi
        s = _cffi.Session(impersonate="chrome136")
        if proxy:
            s.proxies = {"https": proxy, "http": proxy}
        r = s.get("https://ipinfo.io/json", timeout=timeout)
        if r.status_code == 200:
            j = r.json()
            ip = j.get("ip", "?")
            loc = f"{j.get('city','?')}/{j.get('region','?')}/{j.get('country','?')}"
            org = j.get("org", "")
            # Trim ASN prefix for brevity: "AS701 Verizon Business" → "Verizon Business"
            if org.startswith("AS"):
                parts = org.split(" ", 1)
                org = parts[1] if len(parts) > 1 else org
            return f"{ip} ({loc}, {org})"
        return f"probe_failed(HTTP {r.status_code})"
    except Exception as e:
        return f"probe_error({str(e)[:50]})"


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
    # Defaults target "one account per ProxySeller sticky rotation (~5 min)"
    # which gives each account a distinct residential IP without tripping
    # OpenAI's "same IP, many accounts" signal.
    min_sleep: int = 300    # seconds
    max_sleep: int = 360    # seconds
    debug: bool = False     # pipe core.* INFO logs into task log


class SingleEmailReq(BaseModel):
    email: Optional[str] = None
    count: int = 0
    proxy: Optional[str] = None


class TestAtReq(BaseModel):
    """Test whether an AT works against ChatGPT Codex backend-api."""
    email: Optional[str] = None          # if set, pull AT from DM/CPA
    access_token: Optional[str] = None   # or pass AT directly
    source: str = "cpa"                  # "cpa" | "dm" — where to fetch AT when only email given
    cpa_file_name: Optional[str] = None  # override: specific CPA auth-file name
    prompt: str = "say hi in 3 words"
    model: str = "gpt-5"
    proxy: Optional[str] = None


class TestRefRegisterReq(BaseModel):
    """Run the vendored lxf746/any-auto-register flow to see if the reference
    impl succeeds where ours fails."""
    email: Optional[str] = None   # auto-generate if None
    domain: str = "aitech.email"
    proxy: Optional[str] = None


class OAuthFreeReq(BaseModel):
    email: Optional[str] = None
    count: int = 0
    category: Optional[str] = None
    proxy: Optional[str] = None
    dry_run: bool = False  # preview only, no OAuth


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
    writeback: bool = False  # also write AT back to DM


class PayReq(BaseModel):
    email: Optional[str] = None
    country: str = "US"
    count: int = 1
    proxy: Optional[str] = None
    plan: str = "team"          # "team" | "plus"
    ui_mode: str = "custom"     # "custom" (new) | "redirect" (old)
    seat_quantity: int = 5      # team only


class MarkPaidReq(BaseModel):
    targets: list[str]  # emails, links, or tokens
    category: str = "enterprise"


class DeactCheckReq(BaseModel):
    emails: list[str]


class TaskProxyReq(BaseModel):
    command: str
    proxy: str  # url or "none" or "clear"


class SubscribeFlowReq(BaseModel):
    target: str  # email | payment_link | AT token
    category: str = "enterprise"
    do_mark_paid: bool = True
    do_writeback: bool = True
    do_oauth_multi: bool = True
    dm_writeback: bool = True  # for oauth_multi step
    seats: int = 9
    proxy: Optional[str] = None


class InviteReq(BaseModel):
    source_email: str
    targets: list[str]
    role: str = "standard-user"


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
#  Shared helpers — extracted for reuse across task runners and endpoints
# ---------------------------------------------------------------------------

def _parse_payment_url(url: str) -> dict:
    """Extract identifiers from either checkout-URL or payments/success-team URL.
    Returns {session_id, account_id} (any may be empty).

    Supports:
      - https://chatgpt.com/checkout/<processor>/cs_live_XXXXX
      - https://chatgpt.com/payments/success-team?stripe_session_id=cs_live_XXXXX&account_id=UUID&...
      - bare cs_live_XXXXX session id
    """
    out = {"session_id": "", "account_id": ""}
    if not url:
        return out
    # Session id: 'cs_live_...' or 'cs_test_...' (alphanumerics after prefix)
    m = re.search(r"cs_(?:live|test)_[A-Za-z0-9]+", url)
    if m:
        out["session_id"] = m.group(0)
    # account_id from success URL query string
    m = re.search(r"[?&]account_id=([0-9a-fA-F-]{16,})", url)
    if m:
        out["account_id"] = m.group(1)
    return out


def _resolve_account_by_input(dm: DataManager, target: str) -> dict | None:
    """Resolve a DM account from email / payment-link / success-URL / AT token."""
    t = (target or "").strip()
    if not t:
        return None

    # 1) Email
    if "@" in t and "chatgpt.com" not in t:
        return dm.find_account(t, include_disabled=True)

    # 2) Payment URL — checkout or payments/success-team
    if "chatgpt.com" in t or "checkout" in t or "cs_live_" in t or "cs_test_" in t:
        parsed = _parse_payment_url(t)
        session_id = parsed["session_id"]
        account_id = parsed["account_id"]

        accounts = dm.list_accounts(include_disabled=True)

        # Primary: match session_id inside stored payment_link
        if session_id:
            for a in accounts:
                pl = a.get("payment_link") or ""
                if pl and session_id in pl:
                    return a

        # Fallback: match team_account_id (from success URL)
        if account_id:
            for a in accounts:
                if (a.get("team_account_id") or "").lower() == account_id.lower():
                    return a

        # Legacy fallback: literal substring match
        for a in accounts:
            pl = a.get("payment_link") or ""
            if pl and (t in pl or pl in t):
                return a
        return None

    # 3) Access token / JWT
    if len(t) > 100 and "." in t:
        claims = decode_jwt_claims(t)
        email = claims.get("https://api.openai.com/profile", {}).get("email", "")
        if email:
            return dm.find_account(email, include_disabled=True)
    return None


def _mark_account_paid(dm: DataManager, acc_id: int, category: str = "enterprise",
                       seats: int = 9) -> dict:
    """Apply subscribed-state field PATCHes to DM account.
    Returns {ok, failed_fields[]}. Each field patched individually with 1 retry."""
    import time as _t
    fields = [
        ("category", category),
        ("status", "active"),
        ("subscription_status", "active"),
        ("subscription_at", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        ("seats_total", seats),
        ("seats_left", seats),
        ("token_context", "free"),
    ]
    failed = []
    for k, v in fields:
        for _ in range(2):
            r = dm.patch_account(acc_id, {k: v})
            if r.get("ok"):
                break
            _t.sleep(0.3)
        else:
            failed.append(k)
    return {"ok": not failed, "failed_fields": failed}


def _writeback_one(dm: DataManager, acc: dict, proxy: str | None,
                    password: str, otp_token: str) -> dict:
    """Fetch fresh ChatGPT session AT for one account and PATCH DM.
    Returns {ok, at, plan_type, account_id, token_context, error}."""
    email = acc.get("email", "")
    acc_id = acc.get("id")
    if not email or not acc_id:
        return {"ok": False, "error": "missing_email_or_id"}

    result = get_chatgpt_session_at(email, password, otp_token, proxy)
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error", "session_failed")}

    at = result["access_token"]
    claims = decode_jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth", {})
    plan_type = auth_info.get("chatgpt_plan_type", "")
    account_id = auth_info.get("chatgpt_account_id", "")
    new_tc = "team" if plan_type in ("team", "enterprise", "business") else "free"

    patch_body = {"access_token": at, "token_context": new_tc}
    if account_id:
        patch_body["account_id"] = account_id
    pr = dm.patch_account(acc_id, patch_body)
    if not pr.get("ok"):
        return {"ok": False, "error": "patch_failed", "at": at,
                "plan_type": plan_type, "account_id": account_id}

    # Save session file
    try:
        session_file = os.path.join(OUTPUT_DIR, f"{email}.session.json")
        with open(session_file, "w") as f:
            json.dump({"email": email, "access_token": at,
                       "session_cookie": result.get("session_cookie", ""),
                       "plan_type": plan_type, "token_context": new_tc,
                       "account_id": account_id,
                       "created_at": datetime.datetime.utcnow().isoformat() + "Z"},
                      f, indent=2)
    except Exception:
        pass

    return {"ok": True, "at": at, "plan_type": plan_type,
            "account_id": account_id, "token_context": new_tc}


def _oauth_multi_one(cpa_admin: CPAMgmt, email: str, password: str,
                      otp_token: str, proxy: str | None,
                      workspace_filter: list | None,
                      writeback: bool, dm: DataManager | None,
                      log_fn) -> dict:
    """Run oauth_login_multi for one account; optionally DM-writeback per WS.
    Returns {ok, workspaces, results[], error}."""
    def _start():
        return cpa_admin.start_oauth()

    multi = oauth_login_multi(
        start_oauth_fn=_start,
        email=email,
        password=password,
        otp_token=otp_token,
        proxy=proxy,
        workspace_filter=workspace_filter,
        log_fn=log_fn,
    )

    if not multi.get("ok") and not multi.get("results"):
        return {"ok": False, "error": multi.get("error"),
                "workspaces": [], "results": []}

    workspaces = multi.get("workspaces", [])
    results = multi.get("results", [])
    final_results = []

    for r in results:
        ws_id = r.get("workspace_id", "?")
        ws_name = r.get("workspace_name", "?")
        ws_kind = r.get("workspace_kind", "?")
        tag = f"{ws_name} ({ws_kind})"

        if not r.get("ok") or not r.get("code"):
            log_fn(f"  ⏭️ {tag}: skipped — {r.get('error', 'no code')}")
            final_results.append({
                "workspace_id": ws_id, "workspace_name": ws_name, "workspace_kind": ws_kind,
                "ok": False, "error": r.get("error", "no_code"),
            })
            continue

        code = r["code"]
        state = r.get("state", "")
        cb_resp = cpa_admin.oauth_callback(state, code)
        if not cb_resp.get("ok"):
            log_fn(f"  ❌ {tag}: callback failed: {cb_resp}")
            final_results.append({
                "workspace_id": ws_id, "workspace_name": ws_name, "workspace_kind": ws_kind,
                "ok": False, "error": f"callback: {cb_resp}",
            })
            continue

        log_fn(f"  ✅ {tag}: callback ok")

        auth = cpa_admin.find_auth_by_email(email)
        dm_written = False
        if auth:
            auth_id = auth.get("id")
            # Auto-configure: priority=100 + websockets=on for new team auths
            cpa_admin.set_priority(auth_id, 100)
            ws_ok = cpa_admin.set_websockets(auth_id, True)
            log_fn(f"     auth_id={auth_id} priority=100, websockets={'on' if ws_ok else 'set-failed'}")

        # DM writeback for this specific workspace
        if writeback and auth and dm:
            # CPA-management schema: list returns flat entries with
            # id_token (parsed JWT claims, incl. chatgpt_account_id) but
            # NOT access_token. Match by workspace id on id_token, then
            # download the matching file to extract the raw AT.
            cpab_at = None
            fresh_files = cpa_admin.list_auth_files()
            for ff in fresh_files:
                if (ff.get("email") or ff.get("account") or "").lower() != email.lower():
                    continue
                if (ff.get("provider") or ff.get("type") or "").lower() != "codex":
                    continue
                id_token = ff.get("id_token") or {}
                if isinstance(id_token, str):
                    id_token = {}
                ff_aid = id_token.get("chatgpt_account_id", "")
                if ff_aid == ws_id:
                    raw = cpa_admin.download_auth_file(ff.get("name") or ff.get("id", ""))
                    if raw:
                        ff_at = raw.get("access_token", "")
                        if ff_at and len(ff_at) > 100:
                            cpab_at = ff_at
                    break

            if cpab_at:
                claims = decode_jwt_claims(cpab_at)
                auth_info = claims.get("https://api.openai.com/auth", {})
                plan_type = auth_info.get("chatgpt_plan_type", "")
                account_id = auth_info.get("chatgpt_account_id", "")
                new_tc = "team" if plan_type in ("team", "enterprise", "business") else "free"

                dm_acc = dm.find_account(email)
                if dm_acc:
                    patch_body = {"access_token": cpab_at, "token_context": new_tc}
                    if account_id:
                        patch_body["team_account_id"] = account_id
                    pr = dm.patch_account(dm_acc["id"], patch_body)
                    dm_written = pr.get("ok", False)
                    if dm_written:
                        log_fn(f"     DM writeback: tc={new_tc}, plan={plan_type}, ws={account_id}")
                    else:
                        log_fn(f"     ⚠️ DM writeback failed")
            else:
                log_fn(f"     ⚠️ CPAB AT for workspace {ws_id} not found")

        final_results.append({
            "workspace_id": ws_id, "workspace_name": ws_name, "workspace_kind": ws_kind,
            "ok": True, "dm_written": dm_written,
        })

    return {"ok": True, "workspaces": workspaces, "results": final_results}


def _invite_via_at(access_token: str, target_emails: list, role: str,
                    proxy: str | None = None) -> dict:
    """Invite team members via ChatGPT backend API using source account AT.
    Returns {ok, invites: [{id, email, role}], errored: [...], error}."""
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return {"ok": False, "error": "curl_cffi not available"}

    claims = decode_jwt_claims(access_token)
    auth_info = claims.get("https://api.openai.com/auth", {})
    account_id = auth_info.get("chatgpt_account_id", "")
    if not account_id:
        return {"ok": False, "error": "no_account_id_in_jwt"}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
    }
    proxies = {"https": proxy, "http": proxy} if proxy else None

    try:
        r = cffi_requests.post(
            f"https://chatgpt.com/backend-api/accounts/{account_id}/invites",
            headers=headers,
            json={"email_addresses": target_emails, "role": role},
            impersonate="chrome136",
            proxies=proxies,
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "error": f"request_failed: {e}"}

    if r.status_code not in (200, 201):
        return {"ok": False, "error": f"http_{r.status_code}: {r.text[:300]}"}

    try:
        data = r.json()
    except Exception:
        return {"ok": False, "error": f"invalid_json: {r.text[:200]}"}

    return {
        "ok": True,
        "account_id": account_id,
        "invites": data.get("account_invites", []),
        "errored": data.get("errored_emails", []),
    }


# ---------------------------------------------------------------------------
#  Shared helpers (reused from main.py logic)
# ---------------------------------------------------------------------------

def _try_codex_login(email: str, password: str, otp_token: str,
                      client_id: str, redirect_uri: str,
                      proxy: str | None) -> dict:
    """Run a fresh Codex-client PKCE OAuth *login* for an existing account.

    Used after the NextAuth session fallback has already succeeded — the
    account exists + has a profile, so login shouldn't retrigger phone
    signup gate. If successful, yields a proper Codex-client AT+RT+id_token
    that passes /backend-api/codex/* authentication.

    Returns {ok, access_token, refresh_token, id_token, error}.
    """
    from urllib.parse import urlencode
    from curl_cffi import requests as cffi_requests
    from core.openai_auth import (
        _gen_pkce, _gen_state, _build_oauth_url,
        oauth_login, TOKEN_URL,
    )

    code_verifier, code_challenge = _gen_pkce()
    state = _gen_state()
    auth_url = _build_oauth_url(client_id, redirect_uri,
                                 code_challenge, state)
    code, _state, err = oauth_login(auth_url, email, password, otp_token, proxy)
    if not code:
        return {"ok": False, "error": f"oauth_login: {err}"}

    # Exchange code for tokens
    try:
        r = cffi_requests.post(
            TOKEN_URL,
            data=urlencode({
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            impersonate="chrome136",
            proxies={"https": proxy, "http": proxy} if proxy else None,
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "error": f"token_exchange_err: {e}"}

    if r.status_code != 200:
        return {"ok": False,
                "error": f"token_exchange_{r.status_code}: {(r.text or '')[:200]}"}
    try:
        d = r.json()
    except Exception:
        return {"ok": False, "error": "token_exchange_invalid_json"}
    return {
        "ok": bool(d.get("access_token")),
        "access_token": d.get("access_token", ""),
        "refresh_token": d.get("refresh_token", ""),
        "id_token": d.get("id_token", ""),
    }


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

    # Probe the outbound IP through the same proxy — shows whether
    # ProxySeller's rotation actually gives us a fresh IP per account.
    egress_ip = _probe_egress_ip(proxy)
    _log(task_id, f"{idx_label} Registering {email} | egress IP: {egress_ip}")

    reg = register_account(email=email, password=password, otp_token=otp_token,
                           client_id=client_id, redirect_uri=redirect_uri, proxy=proxy)
    if not reg["ok"]:
        _log(task_id, f"❌ {email}: {reg.get('error')}")
        return {"email": email, "ok": False, "error": reg.get("error")}

    phone_required = reg.get("phone_required", False)
    at = reg["access_token"]
    rt = reg["refresh_token"]

    # Track Codex-client tokens separately — these are what Codex backend-api
    # actually accepts. ChatGPT NextAuth AT is rejected by /backend-api/codex/*
    # with 401, so without a Codex-client AT, CPA proxy fails on every Codex call.
    codex_at = ""
    codex_rt = ""
    codex_id_token = ""

    if phone_required:
        _log(task_id, f"⚠️ {email}: phone required, trying session fallback")
        sess = get_chatgpt_session_at(email, password, otp_token, proxy)
        if sess["ok"]:
            at = sess["access_token"]
            _log(task_id, f"✅ {email}: session AT obtained (len={len(at)})")
            # Now that the account exists (created via NextAuth about_you),
            # try a fresh Codex PKCE login. If the server gates phone by
            # signup only (not login), we get a Codex-client AT.
            try:
                ct = _try_codex_login(email, password, otp_token,
                                       client_id, redirect_uri, proxy)
                if ct.get("ok"):
                    codex_at = ct.get("access_token", "")
                    codex_rt = ct.get("refresh_token", "")
                    codex_id_token = ct.get("id_token", "")
                    _log(task_id, f"✅ {email}: Codex login ok — Codex AT "
                                  f"(len={len(codex_at)}, RT={len(codex_rt)})")
                else:
                    _log(task_id, f"⚠️ {email}: Codex login failed: "
                                  f"{ct.get('error','?')[:100]}")
            except Exception as e:
                _log(task_id, f"⚠️ {email}: Codex login exception: {e}")
        else:
            _log(task_id, f"⚠️ {email}: session failed: {sess['error']}")
    else:
        _log(task_id, f"✅ {email}: registered (AT={len(at)}, RT={len(rt)})")
        # Not phone-blocked — the reg AT already is Codex-client
        codex_at = at
        codex_rt = rt

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
    if dm_ok:
        _log(task_id, f"✅ {email}: DM ok")
    else:
        err_snippet = str(dm_res.get("error") or dm_res.get("raw") or dm_res)[:200]
        _log(task_id, f"⚠️ {email}: DM failed — status={dm_res.get('status')} {err_snippet}")

    # CPA upload — only when we have a Codex-client AT. The ChatGPT NextAuth
    # session AT (phone-blocked fallback) is rejected by /backend-api/codex/*
    # with 401 Unauthorized, so uploading it just pollutes CPA's free pool
    # with dead entries. Those accounts still sit in DM for future Team
    # upgrade (where oauth-multi produces a usable team-client AT).
    cpa_ok = False
    if codex_at:
        # Normal OAuth path (phone-passing) — try OAuth first for refresh_token,
        # fall back to direct upload with the Codex-client AT we already have.
        if not phone_required:
            cpa_res = _do_cpa_mgmt_oauth(cpa_mgmt, email, password, otp_token, proxy)
            cpa_ok = cpa_res.get("ok", False)
            if cpa_ok:
                _log(task_id, f"✅ {email}: CPA OAuth ok (with RT)")
            else:
                err = str(cpa_res.get("error", ""))
                phone_related = any(x in err for x in (
                    "no_code_extracted", "add_phone", "invalid_auth_step"))
                if not phone_related:
                    _log(task_id, f"⚠️ {email}: CPA OAuth failed: {err[:150]}")
        if not cpa_ok:
            up = cpa_mgmt.upload_codex_auth(email=email, access_token=codex_at,
                                             refresh_token=codex_rt,
                                             id_token=codex_id_token)
            cpa_ok = up.get("ok", False)
            if cpa_ok:
                cpa_mgmt.set_priority(up["name"], 100)
                cpa_mgmt.set_websockets(up["name"], True)
                _log(task_id, f"✅ {email}: CPA upload {up['name']} (prio=100, ws=on)")
            else:
                _log(task_id, f"⚠️ {email}: CPA upload failed — {up.get('error') or up.get('status')}")
    elif at:
        _log(task_id, f"⏭️ {email}: skipping CPA upload — no Codex-client AT "
                      f"(phone-blocked); account waits in DM for Team upgrade")

    return {"email": email, "ok": True, "phone_required": phone_required,
            "has_at": bool(at), "dm_ok": dm_ok, "cpa_ok": cpa_ok}


def _run_register(task_id: str, req: RegisterReq):
    import random
    import logging as _logging

    cfg = CFG
    proxy = _get_proxy(req.proxy, "register")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    client_id = cfg["oauth_client_id"]
    redirect_uri = cfg["oauth_redirect_uri"]
    domains = cfg["domains"]

    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    cpa_mgmt = CPAMgmt(cfg["cpa_mgmt_base"], cfg["cpa_mgmt_bearer"])

    # Debug mode: pipe core.* module logs into the task log
    debug_handler = None
    if getattr(req, "debug", False):
        class _TaskLogHandler(_logging.Handler):
            def emit(self, record):
                try:
                    msg = self.format(record)
                    _log(task_id, f"🔍 {msg}")
                except Exception:
                    pass
        debug_handler = _TaskLogHandler()
        debug_handler.setLevel(_logging.INFO)
        debug_handler.setFormatter(_logging.Formatter("%(name)s | %(message)s"))
        for mod_name in ("core.chatgpt_session", "core.openai_auth", "core.otp"):
            _logging.getLogger(mod_name).addHandler(debug_handler)
            _logging.getLogger(mod_name).setLevel(_logging.INFO)
        _log(task_id, "🔍 Debug log mirroring ON (core.*)")

    fixed_email = (req.email or "").strip() or None
    fixed_domain = (req.domain or "").strip().lstrip("@") or None

    results = []

    try:
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
    finally:
        if debug_handler is not None:
            for mod_name in ("core.chatgpt_session", "core.openai_auth", "core.otp"):
                _logging.getLogger(mod_name).removeHandler(debug_handler)


def _run_writeback(task_id: str, req: SingleEmailReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy, "writeback")
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
    proxy = _get_proxy(req.proxy, "session")
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
    proxy = _get_proxy(req.proxy, "relogin")
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
    proxy = _get_proxy(req.proxy, "oauth")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    # Team pool now on plus.cpa.lsai.uk (CPA-management API, not CPAB)
    cpa_admin = CPAMgmt(cfg["cpa_plus_base"], cfg["cpa_plus_bearer"])

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

        # Verify auth file + auto-config priority=100 + websockets=on
        auth = cpa_admin.find_auth_by_email(email)
        verified = False
        if auth:
            auth_id = auth.get("id")
            plan = auth.get("plan_type", "?")
            cpa_admin.set_priority(auth_id, 100)
            ws_ok = cpa_admin.set_websockets(auth_id, True)
            _log(task_id, f"✅ {email}: auth_id={auth_id}, plan={plan}, priority=100, "
                          f"websockets={'on' if ws_ok else 'set-failed'}")
            verified = True
        else:
            _log(task_id, f"⚠️ {email}: auth file not found in CPA (may take a moment)")

        _log(task_id, f"✅ {email}: OAuth complete")
        results.append({"email": email, "ok": True, "category": category, "verified": verified})

    ok_count = sum(1 for r in results if r["ok"])
    _log(task_id, f"Summary: {ok_count}/{len(results)} succeeded")
    _finish(task_id, results)


def _run_oauth_multi(task_id: str, req: OAuthMultiReq):
    """OAuth all workspaces of one account.
    Thin wrapper around _oauth_multi_one (same helper used by subscribe-flow).
    Ensures consistent priority + websockets auto-config on newly created auths."""
    cfg = CFG
    proxy = _get_proxy(req.proxy, "oauth-multi")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]

    email = (req.email or "").strip()
    if not email:
        _log(task_id, "❌ email is required")
        _finish(task_id, {"ok": False, "error": "email_required"}, "error")
        return

    _log(task_id, f"OAuth ALL workspaces for: {email}")
    if req.workspace_ids:
        _log(task_id, f"Filter: {len(req.workspace_ids)} workspace(s) {req.workspace_ids}")

    cpa_admin = CPAMgmt(cfg["cpa_plus_base"], cfg["cpa_plus_bearer"])
    dm = DataManager(cfg["dm_base"], cfg["dm_token"]) if req.writeback else None

    om = _oauth_multi_one(
        cpa_admin=cpa_admin,
        email=email,
        password=password,
        otp_token=otp_token,
        proxy=proxy,
        workspace_filter=req.workspace_ids,
        writeback=req.writeback,
        dm=dm,
        log_fn=lambda m: _log(task_id, m),
    )

    if not om.get("ok") and not om.get("results"):
        _log(task_id, f"❌ fatal: {om.get('error')}")
        _finish(task_id, om, "error")
        return

    results = om.get("results", [])
    ok_count = sum(1 for r in results if r.get("ok"))
    _log(task_id, f"Summary: {ok_count}/{len(results)} workspaces OAuth'd")
    _finish(task_id, {
        "ok": True,
        "email": email,
        "workspaces": om.get("workspaces", []),
        "results": results,
    })


def _run_subscribe_flow(task_id: str, req: SubscribeFlowReq):
    """
    Unified post-subscription flow:
      1. Resolve target (email/link/token) → DM account
      2. Mark Paid (optional)
      3. Writeback — fetch team session AT → DM (optional)
      4. OAuth Multi-WS → CPAB + DM writeback (optional)
    Each step independently skippable; failures don't block later steps.
    """
    cfg = CFG
    proxy = _get_proxy(req.proxy, "subscribe-flow")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    steps = []  # [{name, ok, detail}]

    # 1) Resolve
    _log(task_id, f"🔍 Resolving target: {req.target[:60]}...")
    acc = _resolve_account_by_input(dm, req.target)
    if not acc:
        _log(task_id, "❌ account not found")
        _finish(task_id, {"ok": False, "error": "account_not_found",
                          "target": req.target[:80], "steps": []}, "error")
        return

    email = acc.get("email", "?")
    acc_id = acc.get("id")
    _log(task_id, f"✅ resolved: {email} (id={acc_id}, cat={acc.get('category','?')}, "
                  f"tc={acc.get('token_context','?')})")

    # 2) Mark Paid
    if req.do_mark_paid:
        _log(task_id, f"[1/3] 📝 Mark Paid → {req.category} ({req.seats} seats)")
        mp = _mark_account_paid(dm, acc_id, req.category, req.seats)
        if mp["ok"]:
            _log(task_id, f"  ✅ all fields updated")
            steps.append({"name": "mark_paid", "ok": True})
        else:
            _log(task_id, f"  ⚠️ partial: failed = {mp['failed_fields']}")
            steps.append({"name": "mark_paid", "ok": False,
                          "detail": f"failed_fields: {mp['failed_fields']}"})
        # Refetch account for later steps to see latest state
        acc = dm.find_account(email) or acc
    else:
        _log(task_id, f"[1/3] ⏭️ Mark Paid skipped")

    # 3) Writeback
    if req.do_writeback:
        _log(task_id, f"[2/3] 🔄 Writeback (fetch session AT)")
        if _is_stopped(task_id):
            _log(task_id, "🛑 stopped before writeback")
            _finish(task_id, {"ok": False, "email": email, "steps": steps,
                              "error": "stopped"}, "stopped")
            return
        wb = _writeback_one(dm, acc, proxy, password, otp_token)
        if wb["ok"]:
            _log(task_id, f"  ✅ AT obtained (plan={wb['plan_type']}, tc={wb['token_context']})")
            steps.append({"name": "writeback", "ok": True,
                          "detail": f"plan={wb['plan_type']}, tc={wb['token_context']}"})
        else:
            _log(task_id, f"  ❌ {wb.get('error','?')}")
            steps.append({"name": "writeback", "ok": False,
                          "detail": wb.get("error", "?")})
    else:
        _log(task_id, f"[2/3] ⏭️ Writeback skipped")

    # 4) OAuth Multi-WS
    if req.do_oauth_multi:
        _log(task_id, f"[3/3] 🔐 OAuth Multi-WS → CPAB"
                      + (" (+ DM writeback)" if req.dm_writeback else ""))
        if _is_stopped(task_id):
            _log(task_id, "🛑 stopped before oauth-multi")
            _finish(task_id, {"ok": False, "email": email, "steps": steps,
                              "error": "stopped"}, "stopped")
            return
        cpa_admin = CPAMgmt(cfg["cpa_plus_base"], cfg["cpa_plus_bearer"])
        om = _oauth_multi_one(
            cpa_admin=cpa_admin, email=email,
            password=password, otp_token=otp_token, proxy=proxy,
            workspace_filter=None,
            writeback=req.dm_writeback, dm=dm,
            log_fn=lambda m: _log(task_id, m),
        )
        if om["ok"]:
            n_ok = sum(1 for r in om["results"] if r["ok"])
            n_total = len(om["results"])
            _log(task_id, f"  Summary: {n_ok}/{n_total} workspaces OAuth'd")
            steps.append({"name": "oauth_multi", "ok": n_ok > 0,
                          "detail": f"{n_ok}/{n_total} workspaces",
                          "workspaces": om["workspaces"],
                          "results": om["results"]})
        else:
            _log(task_id, f"  ❌ {om.get('error','?')}")
            steps.append({"name": "oauth_multi", "ok": False,
                          "detail": om.get("error", "?")})
    else:
        _log(task_id, f"[3/3] ⏭️ OAuth Multi-WS skipped")

    ok_count = sum(1 for s in steps if s["ok"])
    _log(task_id, f"🎉 Flow done: {ok_count}/{len(steps)} steps ok")
    _finish(task_id, {
        "ok": True,
        "email": email,
        "account_id": acc_id,
        "steps": steps,
    })


def _scan_deactivated_emails_bulk(otp_token: str, workers: list | None = None,
                                    max_pages: int = 20) -> set:
    """Scan worker inboxes in bulk, return set of emails that received
    OpenAI deactivation notices. Much faster than per-email check_deactivated
    when scanning many accounts at once."""
    import urllib.request
    workers = workers or ["zrfr.dpdns.org", "aitech.email"]  # one per CF worker
    deactivated: set = set()

    for domain in workers:
        page = 0
        while page < max_pages:
            offset = page * 100
            url = f"https://m.{domain}/api/emails?limit=100&offset={offset}"
            try:
                req = urllib.request.Request(url, headers={
                    "Authorization": f"Bearer {otp_token}"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read())
            except Exception as e:
                logger.warning("bulk scan %s page %d: %s", domain, page, e)
                break
            items = data if isinstance(data, list) else (data.get("items") or data.get("data") or [])
            if not items:
                break
            for msg in items:
                subj = (msg.get("subject") or "").lower()
                if "deactivated" in subj and "openai" in subj:
                    rcpt = (msg.get("rcpt_to") or "").lower()
                    if rcpt:
                        deactivated.add(rcpt)
            page += 1
    return deactivated


def _run_oauth_free(task_id: str, req: OAuthFreeReq):
    cfg = CFG
    proxy = _get_proxy(req.proxy, "oauth-free")
    password = cfg["reg_password"]
    otp_token = cfg["otp_token"]
    cpa_mgmt = CPAMgmt(cfg["cpa_mgmt_base"], cfg["cpa_mgmt_bearer"])
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])

    if req.dry_run:
        _log(task_id, "⚠️ DRY-RUN mode — no OAuth will be performed")

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
        # Don't include disabled accounts — they're not worth OAuth-ing
        all_accounts = dm.list_accounts(include_disabled=False)
        _log(task_id, f"DM has {len(all_accounts)} non-disabled accounts")

    # Pre-filter: category, status, already in CPA
    cat_filter = req.category.lower() if req.category else None
    pre_candidates = []
    skipped_cat = 0
    skipped_cpa = 0
    skipped_status = 0
    for acc in all_accounts:
        email = (acc.get("email") or "").lower()
        cat = (acc.get("category") or "").strip().lower()
        st = (acc.get("status") or "").strip().lower()
        sub = (acc.get("subscription_status") or "").strip().lower()

        # Skip explicitly bad states
        if st == "disabled" or sub == "deactivated":
            skipped_status += 1
            continue
        if cat_filter and cat != cat_filter:
            skipped_cat += 1
            continue
        if email in cpa_emails:
            skipped_cpa += 1
            continue
        pre_candidates.append(acc)

    filters = []
    if skipped_status:
        filters.append(f"{skipped_status} disabled/deactivated")
    if skipped_cat:
        filters.append(f"{skipped_cat} category mismatch")
    if skipped_cpa:
        filters.append(f"{skipped_cpa} already in CPA")
    _log(task_id, f"Pre-filter: {len(pre_candidates)} candidates"
         + (f" (skipped {', '.join(filters)})" if filters else ""))

    if not pre_candidates:
        _log(task_id, "⏭️ No candidates to process")
        _finish(task_id, {"ok": True, "dry_run": req.dry_run,
                          "alive": 0, "deactivated": 0, "processed": 0,
                          "results": []}, "done")
        return

    # Batched inbox scan: find all deactivated emails in one sweep
    _log(task_id, f"Bulk-scanning worker inboxes for deactivation notices...")
    deact_set = _scan_deactivated_emails_bulk(otp_token)
    _log(task_id, f"Found {len(deact_set)} deactivated emails across all inboxes")

    # Filter by deactivated set (fallback to per-email check if email has
    # a domain not in the bulk-scanned workers)
    candidates = []
    deactivated_count = 0
    for acc in pre_candidates:
        email = (acc.get("email") or "").lower()
        if email in deact_set:
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

    if req.dry_run:
        preview = [{"email": a.get("email"),
                    "category": a.get("category", "?"),
                    "status": a.get("status", "?"),
                    "token_context": a.get("token_context", "?")}
                   for a in candidates]
        _log(task_id, f"DRY-RUN: {len(candidates)} accounts would be OAuth'd")
        _finish(task_id, {"ok": True, "dry_run": True,
                          "alive": len(candidates),
                          "deactivated": deactivated_count,
                          "would_process": len(candidates),
                          "preview": preview[:50]}, "done")
        return

    _log(task_id, f"Processing {len(candidates)} accounts for free CPA OAuth")
    results = []
    for i, acc in enumerate(candidates):
        if _is_stopped(task_id):
            _log(task_id, "🛑 stopped")
            break
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
    _finish(task_id, results,
            "stopped" if _is_stopped(task_id) else "done")


def _run_health_check(task_id: str, req: HealthCheckReq):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    cfg = CFG
    otp_token = cfg["otp_token"]
    dry_run = req.dry_run
    dm = DataManager(cfg["dm_base"], cfg["dm_token"])
    # Team pool on plus.cpa.lsai.uk — CPA-management API
    cpa_admin = CPAMgmt(cfg["cpa_plus_base"], cfg["cpa_plus_bearer"])

    if dry_run:
        _log(task_id, "⚠️ DRY-RUN mode — no deletions will be performed")

    # 1) List & dedup (access_token fetched per entry — CPA list lacks it)
    _log(task_id, "Fetching CPA auth-files...")
    files = cpa_admin.list_auth_files()
    auths = cpa_admin.extract_codex_auths(files, fetch_access_token=True)
    if not auths:
        _log(task_id, "⏭️ No codex auth entries found")
        _finish(task_id, {"ok": True, "total": 0}, "done")
        return
    _log(task_id, f"Found {len(auths)} codex auth entries (deduplicated)")

    # 2) Verify each token via DM
    _log(task_id, "Verifying tokens via DM...")

    def _check_one(auth):
        at = auth.get("access_token") or ""
        if not at:
            return {"email": auth["email"], "auth_id": auth["auth_id"],
                    "plan_type": auth.get("plan_type", "unknown"),
                    "ok": False, "reason": "no_access_token", "http_status": 0}
        r = dm.verify_token(at)
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
    cpa_admin = CPAMgmt(cfg["cpa_plus_base"], cfg["cpa_plus_bearer"])

    if dry_run:
        _log(task_id, "⚠️ DRY-RUN mode — no deletions or disables will be performed")

    # 1) List DM accounts
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


@app.post("/api/pay")
async def api_pay(req: PayReq):
    """Generate payment link(s). If no email, auto-pick."""
    from core.api import generate_payment_link as _gen_pay
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    proxy = _get_proxy(req.proxy, "pay")
    currency_map = {"US": "USD", "DE": "EUR", "GB": "GBP", "JP": "JPY",
                    "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR",
                    "CA": "CAD", "AU": "AUD", "SG": "SGD"}
    currency = currency_map.get(req.country.upper(), "USD")

    accounts = []
    if req.email:
        acc = dm.find_account(req.email)
        if not acc:
            raise HTTPException(404, f"{req.email} not found")
        accounts = [acc]
    else:
        all_accs = dm.list_accounts()
        candidates = [a for a in all_accs
                      if (a.get("token_context") or "").lower() != "team"
                      and (a.get("status") or "").lower() in ("active", "error")
                      and not a.get("payment_link")
                      and len(a.get("access_token") or "") > 100]
        candidates.sort(key=lambda x: (
            0 if (x.get("token_context") or "").lower() == "free" else 1,
            int(x.get("id") or 10**9)))
        for c in candidates[:req.count * 3]:
            if len(accounts) >= req.count:
                break
            vr = dm.verify_token(c.get("access_token", ""))
            if vr.get("ok"):
                accounts.append(c)
            else:
                tc = (c.get("token_context") or "").lower()
                if tc != "team" and c.get("id"):
                    dm.patch_account(c["id"], {"token_context": "unknown"})

    results = []
    for acc in accounts:
        r = _gen_pay(access_token=acc.get("access_token", ""),
                     plan=req.plan, ui_mode=req.ui_mode,
                     country=req.country.upper(), currency=currency,
                     seat_quantity=req.seat_quantity, proxy=proxy)
        email = acc.get("email", "?")
        if r.get("ok"):
            # Only persist the link for team plan (plus is one-off, no seats).
            if acc.get("id") and req.plan == "team":
                dm.patch_account(acc["id"], {"payment_link": r["payment_link"],
                                             "subscription_status": "pending_payment"})
            results.append({"email": email, "ok": True, "link": r["payment_link"],
                           "workspace": r.get("workspace_name"),
                           "plan": r.get("plan"), "ui_mode": r.get("ui_mode")})
        else:
            results.append({"email": email, "ok": False, "error": r.get("error")})
    return {"results": results}


@app.post("/api/mark-paid")
async def api_mark_paid(req: MarkPaidReq):
    """Mark accounts as subscribed. Accepts emails, payment links, or tokens."""
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    results = []
    for t in req.targets:
        acc = _resolve_account_by_input(dm, t)
        if not acc:
            results.append({"target": t[:40], "ok": False, "error": "not_found"})
            continue
        mp = _mark_account_paid(dm, acc["id"], req.category, seats=9)
        results.append({"email": acc.get("email"), "ok": mp["ok"],
                       "failed_fields": mp["failed_fields"] or None})
    return {"results": results}


@app.post("/api/subscribe-flow")
async def api_subscribe_flow(req: SubscribeFlowReq):
    """Unified post-subscription flow: mark_paid → writeback → oauth_multi."""
    task_id = _create_task("subscribe-flow", req.model_dump())
    threading.Thread(target=_run_subscribe_flow, args=(task_id, req), daemon=True).start()
    return {"task_id": task_id}


@app.post("/api/test-ref-register")
async def api_test_ref_register(req: TestRefRegisterReq):
    """Run the vendored reference-impl registration flow.

    Uses our ProxySeller (or request-override) proxy and our otp-inbox.
    Returns the reference impl's result + log stream.
    """
    from experimental.run_ref_register import run_ref_registration

    proxy = _get_proxy(req.proxy, "test-ref-register")

    # Generate email if not provided
    import random as _r
    import datetime as _dt
    email = (req.email or "").strip()
    if not email:
        domain = (req.domain or "aitech.email").lstrip("@")
        from core.email_gen import FIRST_NAMES
        name = _r.choice(FIRST_NAMES).lower()
        date_part = _dt.date.today().strftime("%y%m%d")
        rand_part = f"{_r.randint(0, 999):03d}"
        email = f"{name}{date_part}{rand_part}@{domain}"

    inbox_base = "https://otp-inbox.z069frame.workers.dev"
    inbox_token = CFG.get("otp_token", "")

    task_id = _create_task("test-ref-register",
                            {"email": email, "proxy_mask": _mask_proxy(proxy)})

    def _worker():
        try:
            result = run_ref_registration(
                email=email, proxy_url=proxy,
                inbox_base=inbox_base, inbox_token=inbox_token)
            for ln in result.get("logs", []):
                _log(task_id, ln)
            _log(task_id, f"[RESULT] success={result.get('success')} "
                          f"error={result.get('error','')[:150]}")
            if result.get("has_at"):
                claims = result.get("claims", {})
                _log(task_id, f"[AT] len={result.get('access_token_len')} "
                              f"client_id={claims.get('client_id')} "
                              f"plan={claims.get('chatgpt_plan_type')}")
            _finish(task_id, result, "done" if result.get("success") else "error")
        except Exception as e:
            _log(task_id, f"[ERROR] {e}")
            _finish(task_id, {"error": str(e)}, "error")

    threading.Thread(target=_worker, daemon=True).start()
    return {"task_id": task_id, "email": email}


@app.post("/api/test-at")
async def api_test_at(req: TestAtReq):
    """Quick smoke test: take an AT (or pull by email) and hit the ChatGPT
    Codex backend-api from the Railway server through the configured proxy.
    Useful for diagnosing 'CPA requests all failing' issues — runs the same
    call CPA's proxy would make."""
    import urllib.parse
    import urllib.request
    import urllib.error

    at = (req.access_token or "").strip()
    account_id = ""
    source_info = ""

    # Resolve AT from email if not provided directly
    if not at and req.email:
        if req.source == "dm":
            dm = DataManager(CFG["dm_base"], CFG["dm_token"])
            acc = dm.find_account(req.email)
            if not acc:
                raise HTTPException(404, f"{req.email} not found in DM")
            at = acc.get("access_token", "")
            source_info = f"dm:{req.email}"
        else:  # cpa
            # Pull from CPA auth file (defaults to -free.json variant)
            name = req.cpa_file_name or f"codex-{req.email}-free.json"
            url = (f"{CFG['cpa_mgmt_base']}/v0/management/auth-files/download"
                   f"?name={urllib.parse.quote(name)}")
            try:
                r = urllib.request.Request(url, method="GET",
                    headers={"Authorization": f"Bearer {CFG['cpa_mgmt_bearer']}"})
                with urllib.request.urlopen(r, timeout=15) as rr:
                    content = json.load(rr)
                at = content.get("access_token", "")
                account_id = content.get("account_id", "") or ""
                source_info = f"cpa:{name}"
            except urllib.error.HTTPError as e:
                raise HTTPException(404, f"CPA fetch failed: HTTP {e.code}")

    if not at or len(at) < 100:
        raise HTTPException(400, "no valid access_token found")

    # Decode account_id from AT claims if still unknown
    if not account_id:
        claims = decode_jwt_claims(at) or {}
        auth = claims.get("https://api.openai.com/auth", {}) or {}
        account_id = auth.get("chatgpt_account_id", "") or ""

    proxy = _get_proxy(req.proxy, "test-at")

    # Probe egress IP first so we know the route
    egress = _probe_egress_ip(proxy, timeout=8)

    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        raise HTTPException(500, "curl_cffi not available")

    s = cffi_requests.Session(impersonate="chrome136")
    if proxy:
        s.proxies = {"https": proxy, "http": proxy}

    results: dict[str, Any] = {
        "source": source_info or "direct_token",
        "at_len": len(at),
        "account_id": account_id,
        "egress_ip": egress,
    }

    # Test A: /backend-api/accounts/check (cheap, no quota burn)
    try:
        r = s.get("https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
                  headers={"Authorization": f"Bearer {at}",
                           "Accept": "*/*",
                           "ChatGPT-Account-ID": account_id},
                  timeout=30)
        results["accounts_check"] = {
            "http": r.status_code,
            "body_snippet": (r.text or "")[:600],
        }
    except Exception as e:
        results["accounts_check"] = {"error": str(e)[:200]}

    # Test B: ChatGPT-hosted Codex endpoint (what CPA currently proxies)
    try:
        r = s.post("https://chatgpt.com/backend-api/codex/responses",
                   headers={"Authorization": f"Bearer {at}",
                            "Content-Type": "application/json",
                            "Accept": "text/event-stream",
                            "ChatGPT-Account-ID": account_id,
                            "OpenAI-Beta": "responses=experimental"},
                   json={
                       "model": req.model,
                       "input": [{"type": "message", "role": "user",
                                  "content": [{"type": "input_text",
                                               "text": req.prompt}]}],
                       "stream": False,
                       "instructions": "You are a helpful assistant. Reply very briefly.",
                   },
                   timeout=60)
        results["codex_responses"] = {
            "http": r.status_code,
            "body_snippet": (r.text or "")[:1000],
        }
    except Exception as e:
        results["codex_responses"] = {"error": str(e)[:200]}

    # Test C: Public API endpoint (api.openai.com/v1/responses)
    try:
        r = s.post("https://api.openai.com/v1/responses",
                   headers={"Authorization": f"Bearer {at}",
                            "Content-Type": "application/json",
                            "OpenAI-Beta": "responses=experimental"},
                   json={
                       "model": req.model,
                       "input": req.prompt,
                       "stream": False,
                   },
                   timeout=60)
        results["api_v1_responses"] = {
            "http": r.status_code,
            "body_snippet": (r.text or "")[:600],
        }
    except Exception as e:
        results["api_v1_responses"] = {"error": str(e)[:200]}

    # Test D: Public API /v1/chat/completions (common fallback)
    try:
        r = s.post("https://api.openai.com/v1/chat/completions",
                   headers={"Authorization": f"Bearer {at}",
                            "Content-Type": "application/json"},
                   json={
                       "model": req.model,
                       "messages": [{"role": "user", "content": req.prompt}],
                       "stream": False,
                   },
                   timeout=60)
        results["api_v1_chat"] = {
            "http": r.status_code,
            "body_snippet": (r.text or "")[:600],
        }
    except Exception as e:
        results["api_v1_chat"] = {"error": str(e)[:200]}

    # Test E: ChatGPT web conversation endpoint
    try:
        r = s.post("https://chatgpt.com/backend-api/conversation",
                   headers={"Authorization": f"Bearer {at}",
                            "Content-Type": "application/json",
                            "Accept": "text/event-stream",
                            "ChatGPT-Account-ID": account_id},
                   json={
                       "action": "next",
                       "messages": [{"id": "msg-1",
                                     "author": {"role": "user"},
                                     "content": {"content_type": "text",
                                                 "parts": [req.prompt]}}],
                       "model": req.model,
                       "parent_message_id": "00000000-0000-0000-0000-000000000000",
                   },
                   timeout=60)
        results["chatgpt_conversation"] = {
            "http": r.status_code,
            "body_snippet": (r.text or "")[:600],
        }
    except Exception as e:
        results["chatgpt_conversation"] = {"error": str(e)[:200]}

    return results


@app.post("/api/invite")
async def api_invite(req: InviteReq):
    """Invite team members using a source account's AT (from DM)."""
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    acc = dm.find_account(req.source_email)
    if not acc:
        raise HTTPException(404, f"{req.source_email} not found in DM")
    at = acc.get("access_token", "")
    if not at or len(at) < 100:
        raise HTTPException(400, "source account has no valid AT")

    proxy = _get_proxy(None, "invite")
    targets = [t.strip() for t in req.targets if t.strip()]
    if not targets:
        raise HTTPException(400, "no target emails")

    result = _invite_via_at(at, targets, req.role, proxy)
    return result


@app.get("/api/watchdog/status")
async def api_watchdog_status():
    """Read watchdog status written by the bot process (if any)."""
    status_file = "/tmp/codex_watchdog.json"
    try:
        with open(status_file, "r") as f:
            data = json.load(f)
        return {"ok": True, **data}
    except FileNotFoundError:
        return {"ok": False, "error": "no_status_file",
                "hint": "watchdog runs inside TG bot — use /watch in Telegram"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/deact-check")
async def api_deact_check(req: DeactCheckReq):
    """Check emails for deactivation."""
    otp_token = CFG.get("otp_token", "")
    results = []
    for email in req.emails:
        r = check_deactivated(email, otp_token)
        results.append({
            "email": email,
            "deactivated": r.get("deactivated", False),
            "matched_count": r.get("matched_count", 0),
            "matches": r.get("matches", []),
            "error": r.get("error"),
        })
    return {"results": results}


@app.get("/api/proxy/tasks")
async def get_task_proxies():
    return {"task_proxies": {k: _mask_proxy(v) if v != _DIRECT else "DIRECT"
                             for k, v in _task_proxies.items()}}


@app.put("/api/proxy/tasks")
async def set_task_proxy(req: TaskProxyReq):
    cmd = req.command.lower()
    raw = req.proxy.strip()
    if raw.lower() == "clear":
        _task_proxies.pop(cmd, None)
        return {"ok": True, "command": cmd, "proxy": None}
    if raw.lower() in ("none", "direct"):
        _task_proxies[cmd] = _DIRECT
        return {"ok": True, "command": cmd, "proxy": "DIRECT"}
    parsed = _parse_proxy(raw)
    if not parsed:
        raise HTTPException(400, f"Invalid proxy: {raw}")
    _task_proxies[cmd] = parsed
    return {"ok": True, "command": cmd, "proxy": _mask_proxy(parsed)}


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
