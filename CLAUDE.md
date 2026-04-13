# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Python CLI toolkit that automates OpenAI/Codex account registration, OAuth login, session token retrieval, and Data Manager writeback. Replaces OpenClaw browser-based cron jobs with headless `curl_cffi` flows.

## Running

```bash
# Install dependencies
pip install -r requirements.txt

# Register new accounts (default 1)
python main.py register [-n COUNT]

# OAuth — team accounts into CPA-B (default: all candidates)
python main.py oauth [-n COUNT] [-e EMAIL]

# Relogin — get free AT for token_context=unknown accounts
python main.py relogin -n COUNT [-e EMAIL]

# Session — get full-permission ChatGPT session AT
python main.py session [-e EMAIL]

# DM Writeback — get team session AT, patch back to DM (default: all candidates)
python main.py dm-writeback [-n COUNT] [-e EMAIL]
```

Single dependency: `curl_cffi>=0.7.0` (browser-impersonating HTTP client).

## Configuration

All runtime config lives in `config.json` at the repo root. Contains domains, API credentials, proxy settings, OAuth client config, and output directory. This file has live secrets — never commit changes to it without scrubbing credentials.

## Architecture

**`main.py`** — CLI entry point using argparse. Subcommands: `register`, `oauth`, `relogin`, `session`, `dm-writeback`. Loads config, sets up logging, orchestrates the workflow.

**`core/openai_auth.py`** — Central module. Drives OpenAI signup (`register_account`) and login (`oauth_login`) flows using PKCE-based OAuth. Handles redirects, consent screens, workspace/org selection. Uses `curl_cffi` sessions for browser impersonation.

**`core/chatgpt_session.py`** — Gets full-permission ChatGPT session AT via the `/api/auth/session` endpoint. Used by `session`, `dm-writeback`, and `relogin` commands.

**`core/api.py`** — API clients (`CPAAdmin`, `CPAMgmt`, `DataManager`) for the surrounding service ecosystem. Handles admin login, account creation/lookup, OAuth flow initiation/completion, auth-file metadata inspection, and candidate selection. Also provides `decode_jwt_claims()`.

**`core/email_gen.py`** — Generates registration emails (name + date + random digits), rotates domains daily. Also generates random display names and birthdates.

**`core/otp.py`** — Polls a mailbox API for email verification codes with retry logic.

**`core/sentinel.py`** — Retrieves Sentinel proof-of-work tokens for OpenAI auth. Has a local fallback if the API is unavailable.

### Data Flow

**Register:** generate email → `register_account()` (signup + OTP + sentinel) → save tokens to `output/<email>.json` → sync to Data Manager (`token_context=free` if AT obtained, `token_context=unknown` otherwise) → trigger CPA mgmt OAuth flow.

**OAuth:** CPA admin login → pick candidates from DM (enterprise/business/plus without team auth in CPA-B) → for each: start OAuth via CPA → `oauth_login()` (password + OTP + redirects) → callback to CPA → verify auth-file → set priority=100. Replaces OpenClaw "OAuth Post-Payment Sync" cron.

**Relogin:** pick candidates from DM with `token_context=unknown` → `get_chatgpt_session_at()` → PATCH DM with AT and `token_context=free`.

**DM Writeback:** pick candidates from DM (enterprise/business with `token_context=free`) → `get_chatgpt_session_at()` → PATCH DM with team AT and `token_context=team`.

### Batch behavior

- `oauth` and `dm-writeback`: `--count` defaults to 0 (all candidates). Specify `-n N` to limit.
- `relogin`: `--count` defaults to 1. Must specify `-n N` for batch.
- `register`: `--count` defaults to 1.

### Candidate selection (DataManager)

| Method | Criteria | Used by |
|--------|----------|---------|
| `pick_oauth_candidates` | status∈(active,error), category∈(enterprise,business,plus), CPA-B has no team auth | `oauth` |
| `pick_writeback_candidates` | status∈(active,error), category∈(enterprise,business), token_context=free | `dm-writeback` |
| `pick_relogin_candidates` | status∈(active,error), token_context=unknown | `relogin` |

All sort by: error status first, then id ascending.

## Output

Generated auth files are saved to the `output/` directory as `<email>.json` and `<email>.session.json`.

## Testing

Tests live in `tests/` and are run with `pytest`.

```bash
pip install -r requirements-dev.txt

pytest                  # offline suite; live probes auto-skipped
pytest --collect-only -q
pytest -m live          # runs the ChatGPT / CPA / OAuth probes; requires config.json + network
```

Every test that hits real external services (ChatGPT backend-api, CPA-B,
`auth.openai.com`, or DataManager) must be decorated with
`@pytest.mark.live`. The default `pytest` run collects but skips them so
CI never touches OpenAI. See `tests/conftest.py` for the stub fixtures
(`stub_config`, `mock_dm`, `mock_cpa_admin`, `mock_cpa_mgmt`) used by
offline tests, and `tests/README.md` for full instructions.
