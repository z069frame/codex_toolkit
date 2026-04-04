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

    def find_account(self, email: str) -> dict | None:
        ok, st, d = _http(
            f"{self.base}/admin/accounts?query={email}",
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
