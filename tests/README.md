# codex_toolkit tests

## Running

```bash
# Install dev deps (first time)
pip install -r requirements-dev.txt

# Run the offline suite. Live-API tests are auto-skipped.
pytest

# Just collect (no execution)
pytest --collect-only -q

# Run the live-API probes. Requires a real config.json and network access.
pytest -m live
```

## Conventions

- **No test hits a live API by default.** Any test that needs real network
  access to ChatGPT, CPA-B, the OAuth endpoint, or DataManager must be
  decorated with `@pytest.mark.live`. These tests are collected but skipped
  unless `pytest -m live` is invoked.
- Offline tests use the fixtures in `conftest.py`:
  - `stub_config` — placeholder config dict (no secrets).
  - `mock_dm` — `DataManager` stub with sensible default return values.
  - `mock_cpa_admin` / `mock_cpa_mgmt` — `CPAAdmin` / `CPAMgmt` stubs.
- Live tests may still read `config.json` (they are only meaningful against
  real credentials) but must never run in CI without explicit opt-in.

## Structure

- `test_workspace_discovery.py` — live probes against
  `POST /backend-api/accounts/check` and the per-account invite endpoints,
  derived from the original `test_workspace_api*.py` spikes.
- `test_invite.py` — invite-endpoint role-variant probe.
- `test_oauth_multi.py` — full multi-workspace OAuth flow plus a
  cookie/session trace used to diagnose inter-iteration state bleed.
