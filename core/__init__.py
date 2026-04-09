import json
import os

_CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
_cfg = None

# Map of config keys → env var names
_ENV_MAP = {
    "domains":              "DOMAINS",               # comma-separated
    "otp_token":            "OTP_TOKEN",
    "reg_password":         "REG_PASSWORD",
    "proxy":                "PROXY",
    "cpa_admin_base":       "CPA_ADMIN_BASE",
    "cpa_admin_user":       "CPA_ADMIN_USER",
    "cpa_admin_password":   "CPA_ADMIN_PASSWORD",
    "cpa_mgmt_base":        "CPA_MGMT_BASE",
    "cpa_mgmt_bearer":      "CPA_MGMT_BEARER",
    "dm_base":              "DM_BASE",
    "dm_token":             "DM_TOKEN",
    "oauth_client_id":      "OAUTH_CLIENT_ID",
    "oauth_redirect_uri":   "OAUTH_REDIRECT_URI",
    "output_dir":           "OUTPUT_DIR",
}


def _config_from_env() -> dict:
    """Build config dict from environment variables."""
    cfg = {}
    for key, env in _ENV_MAP.items():
        val = os.environ.get(env)
        if val is None:
            continue
        if key == "domains":
            cfg[key] = [d.strip() for d in val.split(",") if d.strip()]
        else:
            cfg[key] = val
    return cfg


def load_config(path=None):
    global _cfg
    p = path or _CFG_PATH
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            _cfg = json.load(f)
    else:
        _cfg = {}
    # Env vars override file values
    _cfg.update(_config_from_env())
    # Defaults
    _cfg.setdefault("output_dir", "output")
    _cfg.setdefault("oauth_redirect_uri", "http://localhost:1455/auth/callback")
    return _cfg


def get_config():
    if _cfg is None:
        load_config()
    return _cfg
