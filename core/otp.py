"""
Compatibility shim.

The OTP implementation was refactored into the ``core/otp/`` package
(see ``core/otp/__init__.py`` and ``notes/otp-protocol.md``). Python's
import machinery resolves ``core.otp`` to the sibling package
directory, so in practice this file is NOT imported during normal use.

It is retained temporarily so that any tooling which locates modules
by filename (e.g. stale ``.pyc`` bytecode, packagers, editors) still
finds a valid module. The real API lives in the package.

Delete this file after the Phase 3 caller migration has been verified
in production.
"""
from __future__ import annotations

# Re-export everything from the package for any stray importer that
# somehow reaches this file directly (e.g. via importlib with an
# explicit file path). Under normal ``import core.otp`` resolution,
# the package wins and this code never runs.
from core.otp import *  # noqa: F401,F403
from core.otp import (  # noqa: F401
    InboxProvider,
    MailboxProvider,
    MailServiceOTP,
    OtpAuthError,
    OtpError,
    OtpProvider,
    OtpTransportError,
    fetch_otp,
    get_otp_provider,
    peek_otp,
)
