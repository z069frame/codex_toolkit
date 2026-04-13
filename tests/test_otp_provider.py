"""
Unit tests for the InboxProvider (core.otp package).

Uses a fake HTTP layer by monkey-patching ``urllib.request.urlopen``
inside ``core.otp.inbox_provider`` — the module the provider actually
calls. This isolates behavior from the network while exercising the
real request-building, response-parsing, retry, and skip-code logic.

The tests cover:
    (a) wait_for_code returns the code when the inbox serves one,
    (b) skip_codes skips the given values and returns the next fresh one,
    (c) timeout returns None (the documented no-raise path).
"""
from __future__ import annotations

import io
import json
import unittest
from typing import Any, Callable
from unittest import mock

from core.otp import (
    InboxProvider,
    MailboxProvider,
    OtpProvider,
    get_otp_provider,
)
from core.otp import inbox_provider as inbox_mod


# ---------------------------------------------------------------------------
# Fake HTTP layer
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal urlopen() context-manager replacement."""

    def __init__(self, payload: Any):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._body


def _queue_urlopen(payloads: list[Any]) -> Callable[..., _FakeResponse]:
    """Build a urlopen() replacement that yields payloads FIFO.

    Each call pops one item. ``None`` payload is served as an empty
    ``{}`` response (no OTP). Once the queue is exhausted, the last
    payload repeats forever (simulates the inbox staying in its final
    state).
    """
    state = {"queue": list(payloads), "last": {}}

    def _impl(req, timeout=None):
        if state["queue"]:
            item = state["queue"].pop(0)
            state["last"] = item if item is not None else {}
        return _FakeResponse(state["last"])

    return _impl


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class InboxProviderTests(unittest.TestCase):
    def setUp(self):
        # Zero the poll interval so tests don't actually sleep.
        self.provider = InboxProvider(
            token="test-token",
            url_pattern="https://m.{domain}/api/latest",
            poll_interval=0.0,
            peek_http_timeout=1.0,
            poll_http_timeout=1.0,
        )
        # Short-circuit time.sleep inside the provider.
        self._sleep_patch = mock.patch.object(inbox_mod.time, "sleep", lambda *_a, **_k: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    # -- (a) wait_for_code returns the code ------------------------------

    def test_wait_for_code_returns_injected_code(self):
        fake = _queue_urlopen([{"otp": "123456"}])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            code = self.provider.wait_for_code("alice@example.com", timeout=5.0)
        self.assertEqual(code, "123456")

    def test_wait_for_code_parses_item_shape(self):
        fake = _queue_urlopen([{"item": {"otp": "999111"}}])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            code = self.provider.wait_for_code("bob@example.com", timeout=5.0)
        self.assertEqual(code, "999111")

    def test_wait_for_code_arrives_after_empty_polls(self):
        # First two polls: empty. Third: the code.
        fake = _queue_urlopen([{}, {}, {"otp": "424242"}])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            code = self.provider.wait_for_code("carol@example.com", timeout=30.0)
        self.assertEqual(code, "424242")

    # -- (b) skip_codes behavior -----------------------------------------

    def test_skip_codes_skips_given_values(self):
        # Server serves a stale code twice, then a fresh one.
        fake = _queue_urlopen([
            {"otp": "111111"},
            {"otp": "111111"},
            {"otp": "222222"},
        ])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            code = self.provider.wait_for_code(
                "dave@example.com",
                timeout=30.0,
                skip_codes=frozenset({"111111"}),
            )
        self.assertEqual(code, "222222")

    def test_skip_codes_returns_none_when_only_stale_visible(self):
        # Only the stale code is ever served; within our poll budget we
        # exhaust attempts and return None.
        fake = _queue_urlopen([{"otp": "111111"}])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            code = self.provider.wait_for_code(
                "erin@example.com",
                timeout=3.0,  # 3s / 0.0001s interval is capped, still finite attempts
                skip_codes=frozenset({"111111"}),
            )
        self.assertIsNone(code)

    # -- (c) timeout -----------------------------------------------------

    def test_wait_for_code_times_out_when_inbox_empty(self):
        fake = _queue_urlopen([{}])  # always empty
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            code = self.provider.wait_for_code(
                "frank@example.com",
                timeout=2.0,
            )
        self.assertIsNone(code)

    def test_wait_for_code_zero_timeout_returns_none(self):
        # timeout <= 0 should short-circuit without hitting the network.
        called = {"n": 0}

        def _boom(*_a, **_k):
            called["n"] += 1
            raise AssertionError("urlopen must not be called when timeout<=0")

        with mock.patch.object(inbox_mod.urllib.request, "urlopen", _boom):
            code = self.provider.wait_for_code("gina@example.com", timeout=0.0)
        self.assertIsNone(code)
        self.assertEqual(called["n"], 0)

    # -- peek ------------------------------------------------------------

    def test_peek_returns_current_code(self):
        fake = _queue_urlopen([{"otp": "555555"}])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake):
            self.assertEqual(self.provider.peek("henry@example.com"), "555555")

    def test_peek_returns_none_on_transport_error(self):
        def _raise(*_a, **_k):
            raise OSError("connection refused")

        with mock.patch.object(inbox_mod.urllib.request, "urlopen", _raise):
            self.assertIsNone(self.provider.peek("iris@example.com"))


# ---------------------------------------------------------------------------
# Factory tests
# ---------------------------------------------------------------------------

class FactoryTests(unittest.TestCase):
    def test_factory_returns_inbox_provider_from_namespaced_config(self):
        p = get_otp_provider({
            "otp": {
                "provider": "inbox",
                "inbox": {"token": "abc"},
            }
        })
        self.assertIsInstance(p, InboxProvider)
        self.assertIsInstance(p, OtpProvider)

    def test_factory_legacy_flat_config_still_works(self):
        # Simulates today's config.json (no "otp" namespace; flat keys).
        p = get_otp_provider({"otp_token": "legacy-token"})
        self.assertIsInstance(p, InboxProvider)
        self.assertEqual(p.token, "legacy-token")

    def test_factory_mailbox_returns_stub(self):
        p = get_otp_provider({
            "otp": {
                "provider": "mailbox",
                "mailbox": {"base_url": "https://mail.example.com", "api_key": "k"},
            }
        })
        self.assertIsInstance(p, MailboxProvider)
        with self.assertRaises(NotImplementedError):
            p.peek("x@y")
        with self.assertRaises(NotImplementedError):
            p.wait_for_code("x@y", timeout=1.0)

    def test_factory_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_otp_provider({"otp": {"provider": "nope"}})


# ---------------------------------------------------------------------------
# Legacy shim
# ---------------------------------------------------------------------------

class LegacyShimTests(unittest.TestCase):
    def test_fetch_otp_shim_still_works(self):
        from core.otp import fetch_otp

        fake = _queue_urlopen([{"otp": "777777"}])
        with mock.patch.object(inbox_mod.urllib.request, "urlopen", fake), \
             mock.patch.object(inbox_mod.time, "sleep", lambda *_a, **_k: None):
            code = fetch_otp(
                "user@example.com",
                "example.com",
                "legacy-token",
                max_retries=2,
                retry_interval=0,
            )
        self.assertEqual(code, "777777")


if __name__ == "__main__":
    unittest.main()
