"""
Standalone endpoint for testing the lxf746/any-auto-register ChatGPT
registration flow using our ProxySeller proxy + otp-inbox backend.

Called via POST /api/test-ref-register from the Railway web app.
"""
import os
import sys
import json
import time
import logging
import secrets
import base64
import importlib.util
import urllib.request
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)

# Add vendored reference code to sys.path so `platforms.chatgpt.register`
# resolves to their version (not ours)
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REFAPP_DIR = os.path.join(_THIS_DIR, "refapp")
if _REFAPP_DIR not in sys.path:
    sys.path.insert(0, _REFAPP_DIR)


def _force_load_ref_core_http():
    """Load refapp/core/http_client.py under the module name 'core.http_client'.

    Our project's 'core' package is already imported at FastAPI startup, so
    Python's module cache has sys.modules['core'] = our core. When refapp's
    code does 'from core.http_client import HTTPClient' it hits the cached
    'core' and finds no http_client submodule → ImportError.

    Workaround: manually load refapp's core/http_client.py, register it under
    sys.modules['core.http_client'], and attach it to the cached 'core'
    module's attributes so both access patterns work.
    """
    if "core.http_client" in sys.modules:
        return
    path = os.path.join(_REFAPP_DIR, "core", "http_client.py")
    if not os.path.exists(path):
        raise ImportError(f"refapp core/http_client.py not found at {path}")
    spec = importlib.util.spec_from_file_location("core.http_client", path)
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec so re-entrant imports see it
    sys.modules["core.http_client"] = mod
    # Also ensure 'core' exists with a __path__ the loader can reach;
    # our real 'core' is already there, just pin http_client onto it.
    spec.loader.exec_module(mod)
    import core as _our_core  # noqa — our own core; add http_client attr
    setattr(_our_core, "http_client", mod)


_force_load_ref_core_http()


class _OtpInboxEmailService:
    """Stub that talks to our otp-inbox service."""
    class _ST:
        value = "otp-inbox"
    service_type = _ST()

    def __init__(self, email: str, inbox_base: str, inbox_token: str):
        self.email = email
        self._inbox_base = inbox_base.rstrip("/")
        self._inbox_token = inbox_token

    def create_email(self, config=None):
        return {"email": self.email, "service_id": self.email,
                "token": self.email}

    def get_verification_code(self, email=None, email_id=None, timeout=120,
                              pattern=None, otp_sent_at=None):
        """Matches our core.otp.inbox_provider URL pattern:
        GET https://m.{domain}/api/latest?to=<email>&otp_only=1&format=json
        """
        import re as _re
        start = time.time()
        seen = set()
        pat = _re.compile(pattern or r"(?<!\d)(\d{6})(?!\d)")
        target = email or self.email
        domain = (target.split("@", 1)[1] if "@" in target else "").lower()
        while time.time() - start < timeout:
            try:
                q = urllib.parse.urlencode({
                    "to": target, "otp_only": "1", "format": "json"})
                url = f"https://m.{domain}/api/latest?{q}"
                req = urllib.request.Request(
                    url, headers={"Authorization": f"Bearer {self._inbox_token}"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    raw = r.read().decode("utf-8", "ignore")
                # body may be either {"code": "123456"} or list of emails
                try:
                    body = json.loads(raw)
                except Exception:
                    body = raw
                code = ""
                if isinstance(body, dict):
                    code = str(body.get("code") or body.get("otp") or "")
                    if not code and isinstance(body.get("emails"), list):
                        for em in body["emails"]:
                            m = pat.search(str(em.get("body", "")))
                            if m:
                                code = m.group(1); break
                elif isinstance(body, list):
                    for em in body:
                        if isinstance(em, dict):
                            m = pat.search(str(em.get("body", em.get("text", ""))))
                            if m:
                                code = m.group(1); break
                elif isinstance(body, str):
                    m = pat.search(body)
                    if m: code = m.group(1)

                if code and pat.match(code) and code not in seen:
                    return code
                if code:
                    seen.add(code)
            except Exception as e:
                logger.info("otp fetch err: %s", e)
            time.sleep(5)
        return None

    def update_status(self, success, error=None):
        return None

    @property
    def status(self):
        return None


def run_ref_registration(email: str, proxy_url: str,
                          inbox_base: str, inbox_token: str) -> dict:
    """Run the reference impl's RegistrationEngine end-to-end.

    Returns {success, email, error, access_token_preview, claims, logs, steps}.
    """
    logs: list[str] = []

    def log_fn(msg):
        try:
            logs.append(str(msg))
        except Exception:
            pass

    # Import after sys.path mutation
    try:
        from platforms.chatgpt.register import RegistrationEngine
    except Exception as e:
        return {"success": False, "error": f"import: {e}", "logs": logs}

    email_service = _OtpInboxEmailService(email, inbox_base, inbox_token)

    try:
        engine = RegistrationEngine(
            email_service=email_service,
            proxy_url=proxy_url,
            callback_logger=log_fn,
        )
    except Exception as e:
        return {"success": False, "error": f"construct: {e}", "logs": logs}

    # Force email so _create_email doesn't reset it
    engine.email = email

    try:
        result = engine.run()
    except Exception as e:
        return {"success": False, "error": f"run: {e}", "logs": logs}

    out = {
        "success": bool(result and result.success),
        "email": getattr(result, "email", email),
        "error": getattr(result, "error_message", ""),
        "has_at": bool(getattr(result, "access_token", "")),
        "logs": logs,
    }
    at = getattr(result, "access_token", "") or ""
    if at:
        try:
            parts = at.split(".")
            pad = "=" * ((4 - len(parts[1]) % 4) % 4)
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
            auth = claims.get("https://api.openai.com/auth", {})
            out["access_token_preview"] = at[:40] + "..."
            out["access_token_len"] = len(at)
            out["claims"] = {
                "client_id": claims.get("client_id"),
                "aud": claims.get("aud"),
                "scp": claims.get("scp"),
                "chatgpt_account_id": auth.get("chatgpt_account_id"),
                "chatgpt_plan_type": auth.get("chatgpt_plan_type"),
            }
        except Exception:
            pass
    return out
