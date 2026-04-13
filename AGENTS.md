# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

Python CLI toolkit that automates OpenAI/Codex account registration and OAuth login flows, with downstream synchronization to CPA and Data Manager services.

## Running

```bash
# Install dependencies
pip install -r requirements.txt

# Register a new account
python main.py register

# OAuth login (picks candidate automatically)
python main.py oauth

# OAuth login for a specific email
python main.py oauth --email user@example.com
```

Single dependency: `curl_cffi>=0.7.0` (browser-impersonating HTTP client).

## Configuration

All runtime config lives in `config.json` at the repo root. Contains domains, API credentials, proxy settings, OAuth client config, and output directory. This file has live secrets — never commit changes to it without scrubbing credentials.

## Architecture

**`main.py`** — CLI entry point using argparse. Two subcommands: `register` and `oauth`. Loads config, sets up logging, orchestrates the workflow.

**`core/openai_auth.py`** — Central module. Drives OpenAI signup (`register_account`) and login (`oauth_login`) flows using PKCE-based OAuth. Handles redirects, consent screens, workspace/org selection. Uses `curl_cffi` sessions for browser impersonation.

**`core/api.py`** — API clients (`CPAAdmin`, `CPAMgmt`, `DataManager`) for the surrounding service ecosystem. Handles admin login, account creation/lookup, OAuth flow initiation/completion, and auth-file metadata inspection. Also provides `decode_jwt_claims()`.

**`core/email_gen.py`** — Generates registration emails (name + date + random digits), rotates domains daily. Also generates random display names and birthdates.

**`core/otp.py`** — Polls a mailbox API for email verification codes with retry logic.

**`core/sentinel.py`** — Retrieves Sentinel proof-of-work tokens for OpenAI auth. Has a local fallback if the API is unavailable.

### Data Flow

**Register:** generate email → `register_account()` (signup + OTP verification + sentinel token) → save tokens to `output/<email>.json` → decode JWT → sync to Data Manager → trigger CPA OAuth flow.

**OAuth:** CPA admin login → pick candidate from Data Manager → start OAuth via CPA → `oauth_login()` (password login + OTP + redirects) → send callback to CPA → verify and update priority.

## Output

Generated auth files are saved to the `output/` directory as `<email>.json`.

## Testing

Tests live in `tests/` and are run with `pytest`.

```bash
pip install -r requirements-dev.txt

pytest                  # offline suite; live probes auto-skipped
pytest --collect-only -q
pytest -m live          # runs the ChatGPT / CPA / OAuth probes; requires config.json + network
```

Anything that touches real external services must be decorated with
`@pytest.mark.live`. The default `pytest` run collects them but skips them,
so CI never hits OpenAI / CPA-B. The fixtures `stub_config`, `mock_dm`,
`mock_cpa_admin`, and `mock_cpa_mgmt` in `tests/conftest.py` cover the
offline side.
