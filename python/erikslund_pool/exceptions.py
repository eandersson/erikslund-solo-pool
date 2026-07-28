"""Exception hierarchy for operational failures (all derive from PoolError).

Share/block rejections are deliberately NOT exceptions -- the Stratum hot path
returns ShareResult objects, so a bad share never unwinds the stack.
"""

from typing import Any


class PoolError(Exception):
    """Base class for every erikslund_pool-specific error."""


class ConfigError(PoolError):
    """The pool configuration is missing, unreadable, or has invalid keys/values."""


class WorkError(PoolError):
    """A template could not be turned into valid work (e.g. scriptSig over 100 bytes)."""


class RPCError(PoolError):
    """A bitcoind JSON-RPC call failed (see subclasses for unreachable vs. errored)."""


class RPCConnectionError(RPCError):
    """No configured bitcoind endpoint could provide a usable RPC result."""


class RPCResponseError(RPCError):
    """bitcoind returned a JSON-RPC error object (raw on .error; .code/.message parsed)."""

    def __init__(self, error: Any) -> None:
        self.error = error
        if isinstance(error, dict):
            self.code = error.get("code")
            self.message = error.get("message")
        else:
            self.code = None
            self.message = None
        if self.code is not None and self.message is not None:
            detail = f"RPC error {self.code}: {self.message}"
        elif self.code is not None:
            detail = f"RPC error {self.code}"
        else:
            detail = str(self.message) if self.message is not None else str(error)
        super().__init__(detail)
