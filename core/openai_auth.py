"""
OpenAI auth flows via curl_cffi (no browser needed).

Two main functions:
  - register_account()  : signup flow -> returns AT/RT
  - oauth_login()       : login flow for existing account -> returns (code, state)

Based on: https://github.com/kschen202115/codex_register
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import random
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from curl_cffi import requests as cffi_requests

from .email_gen import random_birthdate, random_display_name
from .otp import fetch_otp
from .sentinel import SENTINEL_URL, build_sentinel_pow_token

logger = logging.getLogger(__name__)

AUTH_BASE = "https://auth.openai.com"
AUTH_URL = f"{AUTH_BASE}/oauth/authorize"
TOKEN_URL = f"{AUTH_BASE}/oauth/token"
SIGNUP_URL = f"{AUTH_BASE}/api/accounts/authorize/continue"
REGISTER_URL = f"{AUTH_BASE}/api/accounts/user/register"
SEND_OTP_URL = f"{AUTH_BASE}/api/accounts/email-otp/send"
RESEND_OTP_URL = f"{AUTH_BASE}/api/accounts/email-otp/resend"
VERIFY_OTP_URL = f"{AUTH_BASE}/api/accounts/email-otp/validate"
CREATE_URL = f"{AUTH_BASE}/api/accounts/create_account"
WORKSPACE_URL = f"{AUTH_BASE}/api/accounts/workspace/select"
PASSWORD_VERIFY_URL = f"{AUTH_BASE}/api/accounts/password/verify"
PHONE_SKIP_URL = f"{AUTH_BASE}/api/accounts/phone/skip"

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"

CHROME_VERSIONS = ["chrome120", "chrome133a", "chrome136"]


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _gen_pkce():
    v = secrets.token_urlsafe(48)
    c = base64.urlsafe_b64encode(
        hashlib.sha256(v.encode("ascii")).digest()
    ).rstrip(b"=").decode()
    return v, c


def _gen_state():
    return secrets.token_urlsafe(16)


_UA_MAP = {
    "chrome120": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "chrome133a": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "chrome136": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
}


def _create_session(proxy=None, impersonate=None):
    chrome = impersonate or random.choice(CHROME_VERSIONS)
    s = cffi_requests.Session(impersonate=chrome)
    # Explicitly set User-Agent so it's included in HTTP headers
    ua = _UA_MAP.get(chrome, _UA_MAP["chrome120"])
    s.headers.update({"user-agent": ua})
    if proxy:
        s.proxies = {"https": proxy, "http": proxy}
    return s, chrome


def _get_cookie(session, name):
    """Get cookie value, handling CookieConflict for multiple domains."""
    try:
        return session.cookies.get(name)
    except Exception:
        for cookie in session.cookies.jar:
            if cookie.name == name and "auth.openai.com" in (cookie.domain or ""):
                return cookie.value
        for cookie in session.cookies.jar:
            if cookie.name == name:
                return cookie.value
        return None


def _extract_callback(url: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return params.get("code", [None])[0], params.get("state", [None])[0]


def _follow_redirects(session, url, max_hops=15):
    for _ in range(max_hops):
        try:
            r = session.get(url, allow_redirects=False, timeout=30)
        except Exception as e:
            code, st = _extract_from_error(e)
            if code:
                return code, st
            raise
        loc = r.headers.get("Location", r.headers.get("location", ""))
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(url, loc)
            if "localhost" in nxt and "/auth/callback" in nxt:
                return _extract_callback(nxt)
            url = nxt
            continue
        if "localhost" in r.url and "code=" in r.url:
            return _extract_callback(r.url)
        return None, None
    return None, None


def _extract_from_error(e):
    m = re.search(r"(https?://localhost[^\s\"'>\]]+)", str(e))
    if m:
        return _extract_callback(m.group(1))
    return None, None


def _safe_json(r) -> dict:
    try:
        return r.json() or {}
    except Exception:
        return {}


def _build_oauth_url(client_id, redirect_uri, code_challenge, state):
    return AUTH_URL + "?" + urlencode({
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": DEFAULT_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    })


def _get_sentinel(session, did, flow):
    """Call sentinel API -> return (sentinel_token, sentinel_header_json).

    Computes a real PoW token via SHA3-512 brute force and submits it
    through the active session so cookies/TLS fingerprint stay consistent.
    Empty PoW was rejected by the server and caused 400 errors on later
    steps (e.g. password /user/register).
    """
    ua = session.headers.get("user-agent") or session.headers.get("User-Agent") \
        or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    try:
        pow_token = build_sentinel_pow_token(ua)
    except Exception as e:
        logger.warning("Sentinel PoW solve failed: %s", e)
        return None, None

    sentinel_body = json.dumps(
        {"p": pow_token, "id": did, "flow": flow},
        separators=(",", ":"),
    )
    try:
        resp = session.post(
            SENTINEL_URL,
            data=sentinel_body,
            headers={
                "Origin": "https://sentinel.openai.com",
                "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "Content-Type": "text/plain;charset=UTF-8",
            },
            timeout=30,
        )
        if resp.status_code == 200:
            token = (resp.json() or {}).get("token")
            if token:
                header = json.dumps(
                    {"p": "", "t": "", "c": token, "id": did, "flow": flow}
                )
                return token, header
            logger.warning("Sentinel API returned no token: %s", resp.text[:200])
        else:
            logger.warning("Sentinel API returned %d: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("Sentinel API failed: %s", e)
    return None, None


def _complete_token_exchange(session, oauth_params, email):
    """
    After login: read workspace from cookie -> select workspace
    -> follow redirects -> exchange code for tokens.
    """
    auth_cookie = _get_cookie(session, "oai-client-auth-session")
    if not auth_cookie:
        return {"ok": False, "error": "no_auth_session_cookie"}

    # Decode cookie (urlsafe base64)
    try:
        seg = auth_cookie.split(".")[0]
        pad = "=" * ((4 - len(seg) % 4) % 4)
        cookie_data = json.loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:
        try:
            cookie_data = json.loads(base64.b64decode(seg + pad))
        except Exception:
            cookie_data = {}

    workspaces = cookie_data.get("workspaces", [])
    workspace_id = workspaces[0]["id"] if workspaces else ""

    if not workspace_id:
        return {"ok": False, "error": "no_workspace_id"}

    logger.info("[token_exchange] %s - selecting workspace", email)
    r = session.post(
        WORKSPACE_URL,
        data=json.dumps({"workspace_id": workspace_id}),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
        },
        timeout=30,
    )

    continue_url = _safe_json(r).get("continue_url", "")
    if not continue_url:
        return {"ok": False, "error": f"no_continue_url (ws_status={r.status_code})"}

    logger.info("[token_exchange] %s - following redirects for code", email)
    code, _ = _follow_redirects(session, continue_url)
    if not code:
        return {"ok": False, "error": "no_code_in_callback"}

    logger.info("[token_exchange] %s - exchanging code for tokens", email)
    r = session.post(
        TOKEN_URL,
        data=urlencode({
            "grant_type": "authorization_code",
            "client_id": oauth_params["client_id"],
            "code": code,
            "redirect_uri": oauth_params["redirect_uri"],
            "code_verifier": oauth_params["code_verifier"],
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    if r.status_code != 200:
        return {"ok": False, "error": f"token_exchange_{r.status_code}: {r.text[:200]}"}

    tokens = r.json()
    return {
        "ok": True,
        "access_token": tokens.get("access_token", ""),
        "refresh_token": tokens.get("refresh_token", ""),
        "id_token": tokens.get("id_token", ""),
        "email": email,
    }


# ---------------------------------------------------------------------------
#  Registration
# ---------------------------------------------------------------------------

def register_account(
    email: str,
    password: str,
    otp_token: str,
    client_id: str = CLIENT_ID,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    proxy: str | None = None,
) -> dict:
    """
    Register a new OpenAI account.
    Returns {ok, access_token, refresh_token, email, error}.
    """
    session, chrome_ver = _create_session(proxy)

    try:
        used_codes = set()

        # === Phase 1: Register ===

        # 1) PKCE + OAuth URL
        code_verifier, code_challenge = _gen_pkce()
        state = _gen_state()
        auth_url = _build_oauth_url(client_id, redirect_uri, code_challenge, state)

        # 2) Visit OAuth URL -> session cookies
        logger.info("[register] %s - visiting oauth URL", email)
        session.get(auth_url, timeout=30)
        did = _get_cookie(session, "oai-did") or ""

        # 3) Sentinel token
        logger.info("[register] %s - fetching sentinel token", email)
        sentinel_token, sentinel_header = _get_sentinel(session, did, "authorize_continue")

        # 4) Submit email
        logger.info("[register] %s - submitting email", email)
        hdrs = {
            "Referer": f"{AUTH_BASE}/create-account",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if sentinel_header:
            hdrs["openai-sentinel-token"] = sentinel_header
        r = session.post(SIGNUP_URL, headers=hdrs,
                         data=json.dumps({"username": {"value": email, "kind": "email"},
                                          "screen_hint": "signup"}),
                         timeout=30)
        if r.status_code != 200:
            return {"ok": False, "error": f"email_submit_{r.status_code}: {r.text[:200]}"}

        resp = _safe_json(r)
        page_type = (resp.get("page") or {}).get("type", "")
        is_existing = page_type == "email_otp_verification"

        if is_existing:
            logger.info("[register] %s - account already exists, OTP auto-sent", email)
        else:
            # 5) Set password
            # NOTE: do NOT attach openai-sentinel-token on /user/register.
            # Session cookies from the previous sentinel-verified call carry
            # the anti-bot check forward; re-sending the header here triggers
            # 400 (reference impl matches this).
            logger.info("[register] %s - setting password", email)
            pwd_hdrs = {
                "Referer": f"{AUTH_BASE}/create-account/password",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            r = session.post(REGISTER_URL, headers=pwd_hdrs,
                             data=json.dumps({"password": password, "username": email}),
                             timeout=30)

            if r.status_code != 200:
                return {"ok": False, "error": f"register_{r.status_code}: {r.text[:300]}"}

            # 6) Send OTP
            logger.info("[register] %s - sending OTP", email)
            r = session.post(SEND_OTP_URL,
                             headers={"Referer": f"{AUTH_BASE}/create-account/password",
                                      "Content-Type": "application/json",
                                      "Accept": "application/json"},
                             timeout=30)
            if r.status_code != 200:
                return {"ok": False,
                        "error": f"send_otp_{r.status_code}: {r.text[:300]}"}
            logger.info("[register] %s - send_otp OK (HTTP 200)", email)

        # 7) Fetch + validate OTP
        domain = email.split("@")[1]
        otp_code = fetch_otp(email, domain, otp_token)
        if not otp_code:
            return {"ok": False, "error": "otp_fetch_failed"}
        used_codes.add(otp_code)

        logger.info("[register] %s - validating OTP: %s", email, otp_code)
        r = session.post(VERIFY_OTP_URL, headers=hdrs,
                         data=json.dumps({"code": otp_code}), timeout=30)
        if r.status_code != 200:
            return {"ok": False, "error": f"otp_validate_{r.status_code}"}

        # 8) Create account (new only)
        if not is_existing:
            logger.info("[register] %s - creating account profile", email)
            r = session.post(CREATE_URL, headers=hdrs,
                             data=json.dumps({"name": random_display_name(),
                                              "birthdate": random_birthdate()}),
                             timeout=30)
            if r.status_code != 200:
                return {"ok": False, "error": f"create_account_{r.status_code}: {r.text[:200]}"}

        # === Phase 2: Token exchange (reuse original PKCE, no re-login) ===
        resp = _safe_json(r)
        continue_url = resp.get("continue_url", "")
        page_type = (resp.get("page") or {}).get("type", "")
        logger.info("[register] %s - after create: page=%s, continue_url=%s",
                     email, page_type, continue_url[:120] if continue_url else "(none)")

        oauth_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }

        # Handle add_phone: account created but Codex OAuth blocked.
        # Return partial success — caller will try alternative AT methods.
        if page_type == "add_phone":
            logger.warning("[register] %s - phone required, account created without tokens", email)
            return {
                "ok": True,
                "access_token": "",
                "refresh_token": "",
                "phone_required": True,
            }

        # Consent page or workspace → complete token exchange
        if page_type in ("workspace", "sign_in_with_chatgpt_codex_consent") or not continue_url:
            return _complete_token_exchange(session, oauth_params, email)

        # Follow continue_url → redirects → extract code
        logger.info("[register] %s - following continue_url for code", email)
        code, _ = _follow_redirects(session, continue_url)
        if not code:
            logger.info("[register] %s - no code from continue_url, trying workspace flow", email)
            return _complete_token_exchange(session, oauth_params, email)

        logger.info("[register] %s - exchanging code for tokens", email)
        r = session.post(
            TOKEN_URL,
            data=urlencode({
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if r.status_code != 200:
            return {"ok": False, "error": f"token_exchange_{r.status_code}: {r.text[:200]}"}

        tokens = r.json()
        return {
            "ok": True,
            "access_token": tokens.get("access_token", ""),
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens.get("id_token", ""),
            "expires_in": tokens.get("expires_in"),
        }

    except Exception as e:
        logger.exception("[register] %s - exception", email)
        return {"ok": False, "error": str(e)}
    finally:
        session.close()


# ---------------------------------------------------------------------------
#  OAuth Login (existing account)
# ---------------------------------------------------------------------------

def oauth_login(
    oauth_url: str,
    email: str,
    password: str,
    otp_token: str,
    proxy: str | None = None,
    skip_codes: set | None = None,
) -> tuple[str | None, str | None, str | None]:
    """
    Login to an existing OpenAI account via OAuth.
    Returns (code, state, error).
    """
    session, _ = _create_session(proxy)

    try:
        # 1) Visit OAuth URL
        logger.info("[oauth] %s - visiting oauth URL", email)
        session.get(oauth_url, timeout=30)
        did = _get_cookie(session, "oai-did") or ""

        # 2) Sentinel
        _, sentinel_header = _get_sentinel(session, did, "authorize_continue")

        # 3) Submit email
        logger.info("[oauth] %s - submitting email", email)
        hdrs = {
            "Referer": f"{AUTH_BASE}/log-in",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if sentinel_header:
            hdrs["openai-sentinel-token"] = sentinel_header
        r = session.post(SIGNUP_URL, headers=hdrs,
                         data=json.dumps({"username": {"value": email, "kind": "email"},
                                          "screen_hint": "login"}),
                         timeout=30)
        if r.status_code != 200:
            return None, None, f"email_submit_{r.status_code}: {r.text[:200]}"

        resp = _safe_json(r)
        page_type = (resp.get("page") or {}).get("type", "")

        # 4) Submit password (if needed)
        if page_type != "email_otp_verification":
            logger.info("[oauth] %s - submitting password", email)
            r = session.post(PASSWORD_VERIFY_URL, headers=hdrs,
                             data=json.dumps({"password": password}), timeout=30)
            if r.status_code != 200:
                return None, None, f"login_{r.status_code}: {r.text[:200]}"
            resp = _safe_json(r)
            page_type = (resp.get("page") or {}).get("type", "")

        # 5) Handle OTP
        if page_type in ("email_otp_verification", "email_otp"):
            domain = email.split("@")[1]
            _skip = set(skip_codes) if skip_codes else set()

            otp_validated = False
            for otp_attempt in range(3):
                if otp_attempt > 0:
                    logger.info("[oauth] %s - resending OTP before attempt %d", email, otp_attempt + 1)
                    session.post(SEND_OTP_URL, headers=hdrs, timeout=15)

                wait = 10 if otp_attempt == 0 else 5
                time.sleep(wait)
                otp_code = fetch_otp(email, domain, otp_token,
                                     max_retries=6, retry_interval=5,
                                     skip_codes=_skip)
                if not otp_code:
                    if otp_attempt < 2:
                        continue
                    return None, None, "otp_fetch_failed"

                logger.info("[oauth] %s - validating OTP: %s", email, otp_code)
                r = session.post(VERIFY_OTP_URL, headers=hdrs,
                                 data=json.dumps({"code": otp_code}), timeout=30)
                if r.status_code == 200:
                    otp_validated = True
                    break

                logger.warning("[oauth] %s - OTP %s failed (HTTP %d)", email, otp_code, r.status_code)
                _skip.add(otp_code)

            if not otp_validated:
                return None, None, "otp_validate_failed"

        # 6) Workspace + redirects
        auth_cookie = _get_cookie(session, "oai-client-auth-session")
        if auth_cookie:
            try:
                seg = auth_cookie.split(".")[0]
                pad = "=" * ((4 - len(seg) % 4) % 4)
                cookie_data = json.loads(base64.urlsafe_b64decode(seg + pad))
            except Exception:
                cookie_data = {}

            workspaces = cookie_data.get("workspaces", [])
            ws_id = workspaces[0]["id"] if workspaces else ""
            if ws_id:
                r = session.post(WORKSPACE_URL, headers={
                    "Content-Type": "application/json",
                    "Referer": f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
                }, data=json.dumps({"workspace_id": ws_id}), timeout=30)
                cont = _safe_json(r).get("continue_url", "")
                if cont:
                    code, st = _follow_redirects(session, cont)
                    if code:
                        return code, st, None

        return None, None, "no_code_extracted"

    except Exception as e:
        code, st = _extract_from_error(e)
        if code:
            return code, st, None
        logger.exception("[oauth] %s - exception", email)
        return None, None, str(e)
    finally:
        session.close()
