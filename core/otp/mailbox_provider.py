"""
MailboxProvider — stub for the future self-hosted mailbox service.

This class intentionally raises :class:`NotImplementedError` on every
public method. It exists now so that:

  * the factory in ``core.otp`` has a registered ``"mailbox"`` backend
    to dispatch to (swap is a one-line config change),
  * the intended constructor + method signatures are frozen for future
    implementers,
  * tests that want to assert "unimplemented backend fails loudly" have
    a stable symbol to target.

When the real implementation lands, replace the method bodies — do NOT
change the signatures without updating ``notes/otp-protocol.md``.
"""
from __future__ import annotations


_NOT_IMPLEMENTED_MSG = (
    "MailboxProvider is a stub. The self-hosted mailbox backend is not "
    "implemented yet. Set config['otp']['provider'] = 'inbox' for now, or "
    "implement core/otp/mailbox_provider.py against the OtpProvider "
    "protocol documented in notes/otp-protocol.md."
)


class MailboxProvider:
    """Future self-hosted mailbox provider. Not yet implemented."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        imap_host: str | None = None,
        imap_port: int | None = None,
        imap_username: str | None = None,
        imap_password: str | None = None,
        peek_timeout_s: float = 10.0,
        poll_interval_s: float = 5.0,
        poll_http_timeout_s: float = 15.0,
        **_extra,
    ) -> None:
        # Stash config so future impl can read it; no side effects.
        self.base_url = base_url
        self.api_key = api_key
        self.imap_host = imap_host
        self.imap_port = imap_port
        self.imap_username = imap_username
        self.imap_password = imap_password
        self._peek_timeout_s = peek_timeout_s
        self._poll_interval_s = poll_interval_s
        self._poll_http_timeout_s = poll_http_timeout_s

    # -- OtpProvider protocol ---------------------------------------------

    def peek(self, email: str) -> str | None:
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def wait_for_code(
        self,
        email: str,
        *,
        timeout: float,
        skip_codes: "frozenset[str] | None" = None,
    ) -> str | None:
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)


__all__ = ["MailboxProvider"]
