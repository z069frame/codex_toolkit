"""Shared pytest fixtures for the codex_toolkit test suite.

No test should hit a live API by default. Tests that must touch the real
ChatGPT / CPA / OAuth endpoints are marked with ``@pytest.mark.live`` and
skipped unless the caller opts in with ``pytest -m live``.

Fixtures provided here:

- ``stub_config`` — a minimal config-like dict with placeholder values, so
  code that calls ``load_config()`` can be monkey-patched without touching
  the real ``config.json`` (which holds live secrets).
- ``mock_dm`` — a ``unittest.mock.MagicMock`` shaped like ``DataManager``.
- ``mock_cpa_admin`` / ``mock_cpa_mgmt`` — analogous mocks for
  ``CPAAdmin`` / ``CPAMgmt``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make the repo root importable so tests can ``from core import ...``.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def pytest_configure(config):
    """Register custom markers so ``pytest --strict-markers`` is happy."""
    config.addinivalue_line(
        "markers",
        "live: test that hits live external APIs (ChatGPT/CPA/OAuth); "
        "skipped unless `pytest -m live` is used.",
    )


def pytest_collection_modifyitems(config, items):
    """Auto-skip ``@pytest.mark.live`` tests unless the caller selected them.

    This means ``pytest`` (no args) collects everything but runs only the
    offline tests. ``pytest -m live`` runs the live probes.
    """
    marker_expr = config.getoption("-m") or ""
    if "live" in marker_expr:
        return  # caller explicitly opted in; don't skip
    skip_live = pytest.mark.skip(
        reason="live-API test; run with `pytest -m live` to enable"
    )
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


@pytest.fixture
def stub_config() -> dict:
    """Minimal config shape used by core modules. No live secrets."""
    return {
        "proxy": None,
        "reg_password": "test-password-not-real",
        "otp_token": "test-otp-token-not-real",
        "cpa_admin_base": "https://cpa-admin.example.invalid",
        "cpa_admin_user": "stub-admin",
        "cpa_admin_password": "stub-password",
        "cpa_mgmt_base": "https://cpa-mgmt.example.invalid",
        "cpa_mgmt_user": "stub-mgmt",
        "cpa_mgmt_password": "stub-password",
        "dm_base": "https://dm.example.invalid",
        "dm_token": "stub-dm-token",
        "oauth_client_id": "stub-client-id",
        "oauth_redirect_uri": "https://example.invalid/callback",
        "output_dir": "output",
        "email_domains": ["example.invalid"],
    }


@pytest.fixture
def mock_dm() -> MagicMock:
    """Stub DataManager with sensible default return shapes."""
    dm = MagicMock(name="DataManager")
    dm.pick_oauth_candidates.return_value = []
    dm.pick_writeback_candidates.return_value = []
    dm.pick_relogin_candidates.return_value = []
    dm.get_account.return_value = None
    dm.upsert_account.return_value = {"ok": True}
    dm.patch_account.return_value = {"ok": True}
    return dm


@pytest.fixture
def mock_cpa_admin() -> MagicMock:
    """Stub CPAAdmin. Login auto-succeeds; no auths by default."""
    cpa = MagicMock(name="CPAAdmin")
    cpa.login.return_value = True
    cpa.list_auth_files.return_value = []
    cpa.extract_codex_auths.return_value = []
    cpa.start_oauth.return_value = {
        "url": "https://auth.openai.com/authorize?stub=1",
        "state": "stub-state",
    }
    cpa.complete_oauth.return_value = {"ok": True}
    return cpa


@pytest.fixture
def mock_cpa_mgmt() -> MagicMock:
    """Stub CPAMgmt."""
    cpa = MagicMock(name="CPAMgmt")
    cpa.login.return_value = True
    cpa.create_account.return_value = {"ok": True, "id": "stub-id"}
    cpa.start_oauth.return_value = {
        "url": "https://auth.openai.com/authorize?stub=1",
        "state": "stub-state",
    }
    cpa.complete_oauth.return_value = {"ok": True}
    return cpa
