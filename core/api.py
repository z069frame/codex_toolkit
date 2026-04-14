"""
CPA (Admin + Management) and Data Manager API clients.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

TIMEOUT = 30


def _http(url, method="GET", headers=None, body=None, timeout=TIMEOUT):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "ignore")
            try:
                j = json.loads(txt) if txt.strip() else {}
            except Exception:
                j = {"raw": txt[:500]}
            return True, r.status, j
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "ignore")
        try:
            j = json.loads(txt) if txt.strip() else {}
        except Exception:
            j = {"raw": txt[:500]}
        return False, e.code, j
    except Exception as e:
        return False, 0, {"error": str(e)}


# ---------------------------------------------------------------------------
#  CPA Admin API (api.lsai.uk)
# ---------------------------------------------------------------------------

class CPAAdmin:
    def __init__(self, base: str, user: str, password: str):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self._token = None

    def _headers(self):
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        }

    def login(self) -> bool:
        ok, st, d = _http(
            f"{self.base}/v0/admin/login",
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            body={"username": self.user, "password": self.password},
        )
        if ok:
            self._token = d.get("token") or (d.get("data") or {}).get("token")
        return bool(self._token)

    def list_auth_files(self) -> list:
        ok, st, d = _http(
            f"{self.base}/v0/admin/auth-files",
            headers=self._headers(),
        )
        if not ok:
            return []
        files = d.get("files") or d.get("auth_files") or d.get("data") or []
        return files if isinstance(files, list) else []

    def start_oauth(self) -> dict:
        """POST /v0/admin/tokens/codex → {url, state}"""
        ok, st, d = _http(
            f"{self.base}/v0/admin/tokens/codex",
            method="POST",
            headers=self._headers(),
            body={},
        )
        return {"ok": ok, "status": st, **d}

    def oauth_callback(self, state: str, code: str) -> dict:
        ok, st, d = _http(
            f"{self.base}/v0/admin/tokens/oauth-callback",
            method="POST",
            headers=self._headers(),
            body={"provider": "codex", "state": state, "code": code},
        )
        return {"ok": ok, "status": st, **d}

    def set_priority(self, auth_id: int, priority: int = 100) -> bool:
        ok, st, d = _http(
            f"{self.base}/v0/admin/auth-files/{auth_id}",
            method="PUT",
            headers=self._headers(),
            body={"priority": priority},
        )
        return ok

    def find_auth_by_email(self, email: str) -> dict | None:
        """Find best codex auth-file for email (prefer team, then latest)."""
        files = self.list_auth_files()
        matches = []
        for f in files:
            content = f.get("content") or {}
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except Exception:
                    continue
            ftype = (content.get("type") or "").lower()
            femail = (content.get("email") or "").lower()
            if femail == email.lower() and "codex" in ftype:
                at = content.get("access_token") or ""
                matches.append({
                    "id": f.get("id"),
                    "email": femail,
                    "has_at": bool(at and len(at) > 100),
                    "has_rt": bool((content.get("refresh_token") or "") and len(content.get("refresh_token", "")) > 10),
                    "plan_type": _detect_plan(at),
                })
        if not matches:
            return None
        team = [m for m in matches if m.get("plan_type") == "team"]
        if team:
            return max(team, key=lambda x: x["id"])
        return max(matches, key=lambda x: x["id"])

    def delete_auth_file(self, auth_id: int) -> bool:
        ok, st, d = _http(
            f"{self.base}/v0/admin/auth-files/{auth_id}",
            method="DELETE",
            headers=self._headers(),
        )
        return ok or st in (200, 204)

    def extract_codex_auths(self, files: list | None = None) -> list:
        """Extract & deduplicate codex auth entries from auth-files.
        Returns list of {email, auth_id, access_token, plan_type}."""
        if files is None:
            files = self.list_auth_files()
        by_key = {}
        for f in files:
            content = f.get("content") or {}
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except Exception:
                    continue
            ftype = str(content.get("type") or "").lower()
            if "codex" not in ftype:
                continue
            email = (content.get("email") or "").strip().lower()
            at = (content.get("access_token") or "").strip()
            auth_id = f.get("id") or 0
            if not email or not at or len(at) < 100:
                continue
            plan = _detect_plan(at)
            key = (email, plan)
            if key not in by_key or auth_id > by_key[key]["auth_id"]:
                by_key[key] = {
                    "email": email,
                    "auth_id": auth_id,
                    "access_token": at,
                    "plan_type": plan,
                }
        return list(by_key.values())

    def collect_auth_ids_for_emails(self, emails: set, files: list | None = None) -> list:
        """Get all raw codex auth-ids matching a set of emails."""
        if files is None:
            files = self.list_auth_files()
        result = []
        for f in files:
            content = f.get("content") or {}
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except Exception:
                    continue
            ftype = str(content.get("type") or "").lower()
            if "codex" not in ftype:
                continue
            femail = (content.get("email") or "").strip().lower()
            if femail in emails:
                result.append({"email": femail, "auth_id": f.get("id")})
        return result

    def has_team_auth_for_email(self, email: str) -> bool:
        files = self.list_auth_files()
        email_lower = email.lower()
        for f in files:
            text = json.dumps(f, ensure_ascii=False).lower()
            if email_lower not in text:
                continue
            if any(x in text for x in ["team", "business", "enterprise"]):
                return True
        return False


# ---------------------------------------------------------------------------
#  CPA Management API (cpa.lsai.uk)
# ---------------------------------------------------------------------------

class CPAMgmt:
    def __init__(self, base: str, bearer: str):
        self.base = base.rstrip("/")
        self.bearer = bearer

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.bearer}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        }

    def get_oauth_url(self) -> dict:
        """GET /v0/management/codex-auth-url → {url, state}"""
        ok, st, d = _http(
            f"{self.base}/v0/management/codex-auth-url",
            headers=self._headers(),
        )
        return {"ok": ok, "status": st, **d}

    def oauth_callback(self, state: str, code: str) -> dict:
        ok, st, d = _http(
            f"{self.base}/v0/management/oauth-callback",
            method="POST",
            headers=self._headers(),
            body={"provider": "codex", "state": state, "code": code},
        )
        return {"ok": ok, "status": st, **d}

    def list_auth_files(self) -> list:
        ok, st, d = _http(
            f"{self.base}/v0/management/auth-files",
            headers=self._headers(),
        )
        if not ok:
            return []
        return d.get("files") or d.get("auth_files") or d.get("data") or []


# ---------------------------------------------------------------------------
#  Data Manager API (a.lsai.uk)
# ---------------------------------------------------------------------------

class DataManager:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.token = token

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def create_account(self, email: str, password: str,
                       access_token: str, account_id: str = "",
                       token_context: str = "") -> dict:
        body = {
            "email": email,
            "password": password,
            "access_token": access_token,
        }
        if account_id:
            body["account_id"] = account_id
        if token_context:
            body["token_context"] = token_context
        ok, st, d = _http(
            f"{self.base}/admin/accounts",
            method="POST",
            headers=self._headers(),
            body=body,
        )
        return {"ok": ok, "status": st, **d}

    def find_account(self, email: str, include_disabled: bool = True) -> dict | None:
        flag = "1" if include_disabled else "0"
        ok, st, d = _http(
            f"{self.base}/admin/accounts?query={email}&include_disabled={flag}",
            headers=self._headers(),
        )
        if not ok:
            return None
        accounts = d.get("accounts") or d.get("data") or []
        if not accounts:
            return None
        for acc in accounts:
            if (acc.get("email") or "").lower() == email.lower():
                return acc
        return accounts[0] if accounts else None

    def list_accounts(self, include_disabled: bool = True) -> list:
        out = []
        off = 0
        flag = "1" if include_disabled else "0"
        while True:
            ok, st, d = _http(
                f"{self.base}/admin/accounts?include_disabled={flag}&limit=200&offset={off}",
                headers=self._headers(),
            )
            if not ok:
                break
            arr = d.get("accounts") or d.get("data") or []
            if not arr:
                break
            out.extend(arr)
            if len(arr) < 200:
                break
            off += 200
        return out

    def patch_account(self, account_id: int, patch: dict) -> dict:
        """PATCH /admin/accounts/{id} — update fields (access_token, token_context, etc.)."""
        ok, st, d = _http(
            f"{self.base}/admin/accounts/{account_id}",
            method="PATCH",
            headers=self._headers(),
            body=patch,
        )
        return {"ok": ok, "status": st, **d}

    def verify_token(self, access_token: str) -> dict:
        """POST /api/token/verify — check if AT is still valid."""
        ok, st, d = _http(
            f"{self.base}/api/token/verify",
            method="POST",
            headers=self._headers(),
            body={"access_token": access_token},
        )
        return {"ok": ok, "status": st, **d}

    def pick_writeback_candidate(self) -> dict | None:
        """
        Pick one A-class candidate for DM Session AT writeback:
        - status in (active, error)
        - category in (enterprise, business)
        - token_context == free (subscribed team account but still has free AT)
        Priority: error first, then by id ascending.
        """
        rows = self.list_accounts()
        candidates = []
        for r in rows:
            st = (r.get("status") or "").strip().lower()
            cat = (r.get("category") or "").strip().lower()
            tc = (r.get("token_context") or "").strip().lower()
            if st not in ("active", "error"):
                continue
            if cat not in ("enterprise", "business"):
                continue
            if tc != "free":
                continue
            candidates.append(r)

        if not candidates:
            return None

        candidates.sort(key=lambda x: (
            0 if (x.get("status") or "").lower() == "error" else 1,
            int(x.get("id") or 10**9),
        ))
        return candidates[0]

    def pick_writeback_candidates(self, count: int = 0) -> list:
        """
        Pick candidates for batch DM writeback.
        count=0 means all candidates.
        """
        rows = self.list_accounts()
        candidates = []
        for r in rows:
            st = (r.get("status") or "").strip().lower()
            cat = (r.get("category") or "").strip().lower()
            tc = (r.get("token_context") or "").strip().lower()
            if st not in ("active", "error"):
                continue
            if cat not in ("enterprise", "business"):
                continue
            if tc != "free":
                continue
            candidates.append(r)

        if not candidates:
            return []

        candidates.sort(key=lambda x: (
            0 if (x.get("status") or "").lower() == "error" else 1,
            int(x.get("id") or 10**9),
        ))
        return candidates if count <= 0 else candidates[:count]

    def pick_relogin_candidate(self) -> dict | None:
        """
        Pick one candidate for relogin:
        - status in (active, error)
        - token_context == unknown (registered but never got AT)
        Priority: error first, then by id ascending.
        """
        rows = self.list_accounts()
        candidates = []
        for r in rows:
            st = (r.get("status") or "").strip().lower()
            tc = (r.get("token_context") or "").strip().lower()
            if st not in ("active", "error"):
                continue
            if tc != "unknown":
                continue
            candidates.append(r)

        if not candidates:
            return None

        candidates.sort(key=lambda x: (
            0 if (x.get("status") or "").lower() == "error" else 1,
            int(x.get("id") or 10**9),
        ))
        return candidates[0]

    def pick_relogin_candidates(self, count: int = 1) -> list:
        """
        Pick multiple candidates for batch relogin.
        Same criteria as pick_relogin_candidate but returns up to `count` candidates.
        """
        rows = self.list_accounts()
        candidates = []
        for r in rows:
            st = (r.get("status") or "").strip().lower()
            tc = (r.get("token_context") or "").strip().lower()
            if st not in ("active", "error"):
                continue
            if tc != "unknown":
                continue
            candidates.append(r)

        if not candidates:
            return []

        candidates.sort(key=lambda x: (
            0 if (x.get("status") or "").lower() == "error" else 1,
            int(x.get("id") or 10**9),
        ))
        return candidates[:count]

    def pick_oauth_candidate(self, cpa: CPAAdmin) -> dict | None:
        """
        Replicate oauth_pick_and_sync.py logic:
        - status in (active, error), not disabled/deactivated
        - category in (enterprise, business, plus)
        - CPA does NOT already have a team/business/enterprise auth for this email
        """
        rows = self.list_accounts()
        candidates = []
        for r in rows:
            st = (r.get("status") or "").strip().lower()
            sub = (r.get("subscription_status") or "").strip().lower()
            cat = (r.get("category") or "").strip().lower()
            if st not in ("active", "error"):
                continue
            if st == "disabled" or sub == "deactivated":
                continue
            if cat not in ("enterprise", "business", "plus"):
                continue
            email = r.get("email") or ""
            if cpa.has_team_auth_for_email(email):
                continue
            candidates.append(r)

        if not candidates:
            return None

        # priority: error first (needs fix), then by id asc
        candidates.sort(key=lambda x: (
            0 if (x.get("status") or "").lower() == "error" else 1,
            int(x.get("id") or 10**9),
        ))
        return candidates[0]

    def pick_oauth_candidates(self, cpa: CPAAdmin, count: int = 0) -> list:
        """
        Pick OAuth candidates. count=0 means all candidates.
        """
        rows = self.list_accounts()
        candidates = []
        for r in rows:
            st = (r.get("status") or "").strip().lower()
            sub = (r.get("subscription_status") or "").strip().lower()
            cat = (r.get("category") or "").strip().lower()
            if st not in ("active", "error"):
                continue
            if st == "disabled" or sub == "deactivated":
                continue
            if cat not in ("enterprise", "business", "plus"):
                continue
            email = r.get("email") or ""
            if cpa.has_team_auth_for_email(email):
                continue
            candidates.append(r)

        if not candidates:
            return []

        candidates.sort(key=lambda x: (
            0 if (x.get("status") or "").lower() == "error" else 1,
            int(x.get("id") or 10**9),
        ))
        return candidates if count <= 0 else candidates[:count]


# ---------------------------------------------------------------------------
#  Payment Link Generation
# ---------------------------------------------------------------------------

def generate_payment_link(
    access_token: str,
    country: str = "US",
    currency: str = "USD",
    seat_quantity: int = 5,
    price_interval: str = "month",
    workspace_name: str | None = None,
    proxy: str | None = None,
) -> dict:
    """
    Generate a ChatGPT Team checkout payment link via POST /backend-api/payments/checkout.

    Args:
        access_token: Valid free-tier ChatGPT access token
        country: Billing country code (US, DE, etc.)
        currency: Currency (USD, EUR, etc.)
        seat_quantity: Number of seats (min 2, default 9)
        workspace_name: Team workspace name (auto-generated if None)
        price_interval: "month" or "year"
        proxy: Optional HTTP/SOCKS proxy

    Returns:
        {ok, payment_link, checkout_session_id, processor, error}
    """
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return {"ok": False, "error": "curl_cffi not available"}

    if not access_token or len(access_token) < 100:
        return {"ok": False, "error": "invalid_access_token"}

    # Derive workspace name from token email if not provided
    if not workspace_name:
        claims = decode_jwt_claims(access_token)
        profile = claims.get("https://api.openai.com/profile", {})
        email = profile.get("email", "")
        prefix = email.split("@")[0] if email else "team"
        import re as _re
        prefix = _re.sub(r"[^a-zA-Z0-9]", "-", prefix)[:24]
        import datetime as _dt
        date_tag = _dt.datetime.utcnow().strftime("%Y%m%d")
        workspace_name = f"team-{prefix}-{date_tag}"

    payload = {
        "plan_name": "chatgptteamplan",
        "team_plan_data": {
            "workspace_name": workspace_name,
            "price_interval": price_interval,
            "seat_quantity": max(2, seat_quantity),
        },
        "billing_details": {
            "country": country,
            "currency": currency,
        },
        "cancel_url": "https://chatgpt.com/#pricing",
        "promo_campaign": {
            "promo_campaign_id": "team-1-month-free",
            "is_coupon_from_query_param": False,
        },
        "checkout_ui_mode": "custom",
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": "PostmanRuntime/7.40.0",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
    }

    proxies = {"https": proxy, "http": proxy} if proxy else None

    try:
        r = cffi_requests.post(
            "https://chatgpt.com/backend-api/payments/checkout",
            headers=headers,
            json=payload,
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

    # Parse response — may be nested in "data"
    inner = data.get("data", data)
    session_id = inner.get("checkout_session_id", "")
    processor = inner.get("processor_entity", "stripe")
    direct_url = inner.get("url", "")

    if direct_url:
        link = direct_url
    elif session_id:
        link = f"https://chatgpt.com/checkout/{processor}/{session_id}"
    else:
        return {"ok": False, "error": f"no_session_id: {data}"}

    return {
        "ok": True,
        "payment_link": link,
        "checkout_session_id": session_id,
        "processor": processor,
        "workspace_name": workspace_name,
    }


# ---------------------------------------------------------------------------
#  Deactivated Check (via otp-inbox /api/emails)
# ---------------------------------------------------------------------------

# OpenAI deactivation email indicators
def _is_deact_email(msg: dict) -> bool:
    """Check if an email is an OpenAI deactivation notice.
    Rule: subject contains both 'openai' and 'deactivated'."""
    subj = (msg.get("subject") or "").lower()
    return "deactivated" in subj and "openai" in subj


def check_deactivated(email: str, otp_token: str) -> dict:
    """
    Check if an OpenAI account has been deactivated by searching
    the otp-inbox mailbox for deactivation notice emails.

    Uses GET https://m.<domain>/api/emails?to=<email>&limit=50

    Returns {"deactivated": bool, "matched_count": int, "matches": [...]}
    """
    domain = email.split("@", 1)[-1] if "@" in email else ""
    if not domain:
        return {"deactivated": False, "error": "invalid_email"}

    url = f"https://m.{domain}/api/emails?to={email}&limit=50"
    headers = {"Authorization": f"Bearer {otp_token}"}
    ok, st, d = _http(url, headers=headers)
    if not ok:
        logger.warning("check_deactivated failed for %s: status=%d %s", email, st, d)
        return {"deactivated": False, "error": f"http_{st}"}

    # d can be a list or {"items": [...]} or {"data": [...]}
    emails = d if isinstance(d, list) else (d.get("items") or d.get("data") or [])

    matches = []
    for msg in emails:
        if not _is_deact_email(msg):
            continue
        matches.append({
            "subject": msg.get("subject", ""),
            "from": msg.get("mail_from", ""),
            "date": msg.get("created_at", ""),
        })

    return {
        "deactivated": len(matches) > 0,
        "matched_count": len(matches),
        "matches": matches[:5],
    }


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _detect_plan(access_token: str) -> str:
    if not access_token or len(access_token) < 100:
        return "unknown"
    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return "unknown"
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        d = json.loads(base64.urlsafe_b64decode(payload))
        return d.get("https://api.openai.com/auth", {}).get("chatgpt_plan_type", "unknown")
    except Exception:
        return "unknown"


def decode_jwt_claims(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}
