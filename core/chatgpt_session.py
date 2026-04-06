"""
ChatGPT Web Session — 纯脚本获取完整权限 AT。

直接在 ChatGPT NextAuth OAuth 上下文中完成 auth.openai.com 登录,
OTP 验证成功后 auth.openai.com 返回 chatgpt.com callback URL,
访问该 URL 触发 NextAuth 设置 session cookie,
最后用 session cookie 换取完整权限 AT。

ChatGPT OAuth scopes (client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH):
  openid, email, profile, offline_access,
  model.request, model.read, organization.read, organization.write

关键发现:
  - OTP validate 接口直接返回 continue_url 指向 chatgpt.com/api/auth/callback/openai
  - 不需要额外的 workspace/select 步骤
  - follow callback URL → NextAuth 设置 session cookie → exchange for AT

用法:
  result = get_chatgpt_session_at(email, password, otp_token, proxy)
"""
from __future__ import annotations

import base64
import json
import logging
import time

from curl_cffi import requests as cffi_requests

from .openai_auth import (
    _get_cookie,
    _get_sentinel,
    _safe_json,
    AUTH_BASE,
    SIGNUP_URL,
    PASSWORD_VERIFY_URL,
    SEND_OTP_URL,
    VERIFY_OTP_URL,
    WORKSPACE_URL,
)
from .otp import fetch_otp, peek_otp

logger = logging.getLogger(__name__)

CHATGPT_BASE = "https://chatgpt.com"


def _create_chatgpt_session(proxy=None):
    """Create session with chrome136 — required for chatgpt.com (other versions get 403)."""
    s = cffi_requests.Session(impersonate="chrome136")
    if proxy:
        s.proxies = {"https": proxy, "http": proxy}
    return s


def _extract_session_cookie(session) -> str | None:
    """
    从 cookie jar 中提取 NextAuth session token.
    NextAuth 对大 cookie 会拆分为 chunked cookies:
      __Secure-next-auth.session-token          (单个)
      __Secure-next-auth.session-token.0 + .1   (chunked)
    """
    # Try single cookie first
    for cookie in session.cookies.jar:
        if cookie.name == "__Secure-next-auth.session-token":
            return cookie.value

    # Try chunked cookies (.0, .1, .2, ...)
    chunks = {}
    for cookie in session.cookies.jar:
        if cookie.name.startswith("__Secure-next-auth.session-token."):
            try:
                idx = int(cookie.name.rsplit(".", 1)[1])
                chunks[idx] = cookie.value
            except (ValueError, IndexError):
                continue

    if chunks:
        combined = "".join(chunks[i] for i in sorted(chunks.keys()))
        logger.info("Assembled chunked session cookie from %d parts (total len=%d)",
                     len(chunks), len(combined))
        return combined

    return None


def _build_session_cookie_header(session_cookie: str) -> str:
    """
    Build cookie header for session exchange.
    If cookie is large (>3800 bytes), split into NextAuth chunked format.
    """
    CHUNK_SIZE = 3800
    if len(session_cookie) <= CHUNK_SIZE:
        return f"__Secure-next-auth.session-token={session_cookie}"

    # Split into chunks
    parts = []
    for i in range(0, len(session_cookie), CHUNK_SIZE):
        chunk = session_cookie[i:i + CHUNK_SIZE]
        parts.append(f"__Secure-next-auth.session-token.{len(parts)}={chunk}")
    return "; ".join(parts)


def _exchange_session_for_at(session, session_cookie: str) -> dict | None:
    """用 session cookie 换取完整权限 AT (GET /api/auth/session)."""
    cookie_header = _build_session_cookie_header(session_cookie)
    headers = {
        "accept": "application/json",
        "user-agent": session.headers.get("User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
        "cookie": cookie_header,
        "referer": f"{CHATGPT_BASE}/",
    }

    r = session.get(f"{CHATGPT_BASE}/api/auth/session", headers=headers, timeout=30)

    if r.status_code != 200:
        logger.error("session exchange failed: HTTP %d - %s", r.status_code, r.text[:200])
        return None

    data = _safe_json(r)
    at = data.get("accessToken")
    if not at:
        logger.error("session exchange returned no accessToken: %s", str(data)[:200])
        return None

    return {
        "access_token": at,
        "user": data.get("user", {}),
        "expires": data.get("expires"),
    }


def get_chatgpt_session_at(
    email: str,
    password: str,
    otp_token: str,
    proxy: str | None = None,
) -> dict:
    """
    纯脚本获取 ChatGPT Web 完整权限 AT。

    Returns: {ok, access_token, session_cookie, user, expires, email, error}
    """
    session = _create_chatgpt_session(proxy)

    try:
        # ── Step 1: chatgpt.com → CSRF → NextAuth signin ──
        logger.info("[chatgpt] %s - visiting chatgpt.com", email)
        session.get(CHATGPT_BASE, timeout=30)

        logger.info("[chatgpt] %s - fetching CSRF", email)
        r = session.get(f"{CHATGPT_BASE}/api/auth/csrf", timeout=15)
        csrf = _safe_json(r).get("csrfToken", "")
        if not csrf:
            return {"ok": False, "error": "no_csrf_token"}

        logger.info("[chatgpt] %s - NextAuth signin (provider: openai)", email)
        r = session.post(
            f"{CHATGPT_BASE}/api/auth/signin/openai",
            data=f"callbackUrl=%2F&csrfToken={csrf}&json=true",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "referer": f"{CHATGPT_BASE}/auth/login",
            },
            timeout=30,
        )
        signin_data = _safe_json(r)
        auth_url = signin_data.get("url", "")
        if not auth_url:
            return {"ok": False, "error": f"no_signin_url: HTTP {r.status_code} - {r.text[:300]}"}

        logger.info("[chatgpt] %s - auth URL: %s", email, auth_url[:200])

        # ── Step 2: Follow to auth.openai.com ──
        logger.info("[chatgpt] %s - following to auth.openai.com", email)
        r = session.get(auth_url, timeout=30)
        logger.info("[chatgpt] %s - landed: %s (HTTP %d)", email, r.url[:120], r.status_code)

        did = _get_cookie(session, "oai-did") or ""

        # ── Step 3: Sentinel PoW ──
        logger.info("[chatgpt] %s - solving sentinel", email)
        _, sentinel_header = _get_sentinel(session, did, "authorize_continue")

        # ── Note existing OTP (but don't pre-skip it) ──
        # OpenAI OTPs are valid for multi-use within TTL; and after validate,
        # OpenAI throttles sending a new OTP to the same address for ~60s.
        # So the "stale" OTP from the previous register-phase validate is
        # often still valid and sometimes the ONLY code we'll see. We try it
        # first; if validate fails (HTTP != 200) we'll add it to skip_codes
        # and wait for a new one.
        domain = email.split("@")[1]
        existing_otp = peek_otp(email, domain, otp_token)
        skip_codes: set = set()
        if existing_otp:
            logger.info("[chatgpt] %s - cached OTP present: %s (will try first)",
                         email, existing_otp)

        # ── Step 4: Submit email ──
        logger.info("[chatgpt] %s - submitting email", email)
        hdrs = {
            "Referer": f"{AUTH_BASE}/log-in",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if sentinel_header:
            hdrs["openai-sentinel-token"] = sentinel_header

        r = session.post(
            SIGNUP_URL, headers=hdrs,
            data=json.dumps({
                "username": {"value": email, "kind": "email"},
                "screen_hint": "login",
            }),
            timeout=30,
        )
        if r.status_code != 200:
            return {"ok": False, "error": f"email_submit_{r.status_code}: {r.text[:200]}"}

        resp = _safe_json(r)
        page_type = (resp.get("page") or {}).get("type", "")
        # 有时 email 提交后直接返回 callback URL (已登录态)
        continue_url = resp.get("continue_url", "")
        logger.info("[chatgpt] %s - after email: page=%s, continue_url=%s",
                     email, page_type, continue_url[:100] if continue_url else "(none)")

        # ── Step 5: Submit password (if needed) ──
        if page_type == "login_password":
            logger.info("[chatgpt] %s - submitting password", email)
            r = session.post(
                PASSWORD_VERIFY_URL, headers=hdrs,
                data=json.dumps({"password": password}),
                timeout=30,
            )
            if r.status_code != 200:
                return {"ok": False, "error": f"password_{r.status_code}: {r.text[:200]}"}
            resp = _safe_json(r)
            page_type = (resp.get("page") or {}).get("type", "")
            continue_url = resp.get("continue_url", "")
            logger.info("[chatgpt] %s - after password: page=%s", email, page_type)

        # ── Step 6: OTP ──
        if page_type in ("email_otp_verification", "email_otp"):
            # Email submission already triggered OTP — wait for it to arrive.
            # NOTE: observed MX delivery latency on self-hosted domains is
            # up to ~140s (aitech.email via residential proxy). Poll windows
            # below must cover that or we'll miss fresh OTPs.
            otp_validated = False
            for otp_attempt in range(3):
                # First attempt: just wait for the auto-sent OTP; later attempts: resend first
                if otp_attempt > 0:
                    logger.info("[chatgpt] %s - resending OTP before attempt %d", email, otp_attempt + 1)
                    session.post(SEND_OTP_URL, headers=hdrs, timeout=15)

                wait = 10 if otp_attempt == 0 else 5
                logger.info("[chatgpt] %s - waiting %ds for OTP (attempt %d, skip: %s)",
                            email, wait, otp_attempt + 1, skip_codes)
                time.sleep(wait)

                # ~180s window per fetch: enough for slow MX delivery paths
                otp_code = fetch_otp(email, domain, otp_token,
                                     max_retries=18, retry_interval=10,
                                     skip_codes=skip_codes)
                if not otp_code:
                    if otp_attempt < 2:
                        logger.info("[chatgpt] %s - OTP not received, will retry", email)
                        continue
                    return {"ok": False, "error": "otp_fetch_failed"}

                logger.info("[chatgpt] %s - validating OTP: %s", email, otp_code)
                r = session.post(
                    VERIFY_OTP_URL, headers=hdrs,
                    data=json.dumps({"code": otp_code}),
                    timeout=30,
                )
                if r.status_code == 200:
                    otp_validated = True
                    break

                # OTP expired or wrong — mark as stale and retry
                logger.warning("[chatgpt] %s - OTP %s failed (HTTP %d), will retry",
                               email, otp_code, r.status_code)
                skip_codes.add(otp_code)

            if not otp_validated:
                return {"ok": False, "error": f"otp_validate_failed_after_retries"}

            # OTP validate 返回 continue_url → chatgpt.com callback!
            resp = _safe_json(r)
            continue_url = resp.get("continue_url", "")
            page_type = (resp.get("page") or {}).get("type", "")
            logger.info("[chatgpt] %s - OTP validated! page=%s, continue_url=%s",
                         email, page_type, continue_url[:200] if continue_url else "(none)")

        # ── Step 7: Workspace selection (for team/multi-workspace accounts) ──
        if page_type == "workspace":
            logger.info("[chatgpt] %s - workspace selection required (team account)", email)
            auth_cookie = _get_cookie(session, "oai-client-auth-session")
            if auth_cookie:
                try:
                    seg = auth_cookie.split(".")[0]
                    pad = "=" * ((4 - len(seg) % 4) % 4)
                    cookie_data = {}
                    for decode_fn in (base64.urlsafe_b64decode, base64.b64decode):
                        try:
                            cookie_data = json.loads(decode_fn(seg + pad))
                            break
                        except Exception:
                            continue
                    workspaces = cookie_data.get("workspaces", [])
                    # Prefer organization workspace (team) over personal
                    org_ws = next((w for w in workspaces if w.get("kind") == "organization"), None)
                    ws = org_ws or (workspaces[0] if workspaces else None)
                    if ws:
                        ws_id = ws["id"]
                        logger.info("[chatgpt] %s - selecting workspace: %s (%s, kind=%s)",
                                     email, ws_id, ws.get("name"), ws.get("kind"))
                        r = session.post(
                            WORKSPACE_URL,
                            headers={"Content-Type": "application/json",
                                     "Accept": "application/json",
                                     "Referer": f"{AUTH_BASE}/workspace"},
                            data=json.dumps({"workspace_id": ws_id}),
                            timeout=30,
                        )
                        ws_resp = _safe_json(r)
                        continue_url = ws_resp.get("continue_url", "")
                        page_type = (ws_resp.get("page") or {}).get("type", "")
                        logger.info("[chatgpt] %s - workspace select: page=%s, continue_url=%s",
                                     email, page_type, continue_url[:150] if continue_url else "(none)")
                    else:
                        logger.warning("[chatgpt] %s - no workspaces in cookie", email)
                except Exception as e:
                    logger.warning("[chatgpt] %s - workspace decode error: %s", email, e)

        # ── Step 8: Follow continue_url (chatgpt.com callback) ──
        if continue_url and "chatgpt.com" in continue_url:
            logger.info("[chatgpt] %s - following ChatGPT callback URL", email)
            r = session.get(continue_url, timeout=30)
            logger.info("[chatgpt] %s - callback redirect landed: %s (HTTP %d)",
                         email, r.url[:150], r.status_code)
        elif continue_url and continue_url != "https://auth.openai.com/workspace":
            logger.info("[chatgpt] %s - following continue_url: %s", email, continue_url[:150])
            r = session.get(continue_url, timeout=30)
            logger.info("[chatgpt] %s - redirect landed: %s (HTTP %d)",
                         email, r.url[:150], r.status_code)

        # ── Step 9: Extract session cookie ──
        session_cookie = _extract_session_cookie(session)
        if not session_cookie:
            logger.info("[chatgpt] %s - retrying chatgpt.com visit", email)
            session.get(CHATGPT_BASE, timeout=30)
            session_cookie = _extract_session_cookie(session)

        if not session_cookie:
            all_cookies = [(c.name, c.domain, c.value[:20] + "...")
                           for c in session.cookies.jar]
            logger.error("[chatgpt] %s - no session cookie. Cookies: %s", email, all_cookies)
            return {"ok": False, "error": "no_session_cookie_obtained"}

        logger.info("[chatgpt] %s - session cookie obtained (len=%d)", email, len(session_cookie))

        # ── Step 10: Get AT from /api/auth/session (session already has all cookies) ──
        r = session.get(f"{CHATGPT_BASE}/api/auth/session",
                        headers={"accept": "application/json", "referer": f"{CHATGPT_BASE}/"},
                        timeout=30)
        result = _safe_json(r) if r.status_code == 200 else {}
        at_from_session = result.get("accessToken")

        if not at_from_session:
            # Fallback: try with manually constructed cookie header (for compatibility)
            logger.info("[chatgpt] %s - direct session had no AT, trying manual cookie", email)
            fb_result = _exchange_session_for_at(session, session_cookie)
            if fb_result:
                result = {"accessToken": fb_result["access_token"],
                          "user": fb_result.get("user", {}),
                          "expires": fb_result.get("expires")}
                at_from_session = result.get("accessToken")

        if not at_from_session:
            logger.error("[chatgpt] %s - no accessToken in session response: %s",
                         email, str({k: v for k, v in result.items() if k != "WARNING_BANNER"})[:300])
            return {"ok": False, "error": "no_access_token_in_session"}

        logger.info("[chatgpt] %s - SUCCESS! Full-permission AT (len=%d)", email, len(at_from_session))

        return {
            "ok": True,
            "access_token": at_from_session,
            "session_cookie": session_cookie,
            "user": result.get("user", {}),
            "expires": result.get("expires"),
            "email": email,
        }

    except Exception as e:
        logger.exception("[chatgpt] %s - exception", email)
        return {"ok": False, "error": str(e)}
    finally:
        session.close()
