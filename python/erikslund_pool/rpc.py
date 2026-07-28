"""Minimal synchronous bitcoind JSON-RPC client with failover.

Calls are blocking; the pool runs them off the event loop via asyncio.to_thread.
Connection failures and endpoint-unavailable RPC errors advance to the next endpoint.
Other RPC errors are terminal.
"""

import base64
import logging
import threading
import time
import urllib.error
import urllib.request

import msgspec

from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.exceptions import RPCResponseError
from erikslund_pool.util import redact_url

LOG = logging.getLogger(__name__)

# Failover is sticky; how often maybe_failback() probes the primary to switch back.
FAILBACK_PROBE_SECONDS = 60.0
ENDPOINT_UNAVAILABLE_RPC_CODES = frozenset({-9, -10, -28})


class BitcoindRPC:
    def __init__(self, url, user, password, timeout=30.0, failover=None):
        # `failover`: optional (url, user, password) endpoints tried after the primary.
        endpoints = [(url, user, password)] + list(failover or [])
        self._endpoints = [self._resolve(endpoint_url, endpoint_user, endpoint_password)
                           for (endpoint_url, endpoint_user, endpoint_password) in endpoints]
        self.url = self._endpoints[0][0]  # resolved primary URL; read by tests
        self.timeout = timeout
        self._state_lock = threading.Lock()
        self._current = 0
        self._id = 0
        self._last_failback_probe = float("-inf")
        self._pending_failback_tip: str | None = None

    @staticmethod
    def _resolve(url, user, password):
        if not url.startswith("http"):
            url = "http://" + url
        return url, base64.b64encode(f"{user}:{password}".encode()).decode()

    def _post(self, url, auth, payload):
        """POST to one endpoint. Returns the decoded body, or raises
        RPCConnectionError if the endpoint is unreachable / unparseable."""
        request = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return msgspec.json.decode(response.read())
        except urllib.error.HTTPError as e:
            # Core sends JSON-RPC errors inside HTTP 500 responses.
            try:
                return msgspec.json.decode(e.read())
            except Exception as parse_error:
                raise RPCConnectionError(f"HTTP {e.code} from bitcoind: {e.reason}") from parse_error
        except (urllib.error.URLError, OSError, ValueError) as e:
            # redact_url so embedded credentials don't reach the log.
            raise RPCConnectionError(f"bitcoind RPC failed at {redact_url(url)}: {e}") from e

    def _next_request_id(self) -> int:
        with self._state_lock:
            self._id += 1
            return self._id

    def call(self, method, params=None):
        payload = msgspec.json.encode(
            {
                "jsonrpc": "1.0",
                "id": self._next_request_id(),
                "method": method,
                "params": params or [],
            }
        )
        count = len(self._endpoints)
        with self._state_lock:
            start = self._current
        last_error = None
        for offset in range(count):
            index = (start + offset) % count
            url, auth = self._endpoints[index]
            try:
                body = self._post(url, auth, payload)
            except RPCConnectionError as e:
                last_error = e
                continue
            if body.get("error"):
                response_error = RPCResponseError(body["error"])
                if response_error.code not in ENDPOINT_UNAVAILABLE_RPC_CODES:
                    raise response_error
                last_error = response_error
                continue
            switched = False
            if index != start:
                with self._state_lock:
                    if self._current == start:
                        self._current = index
                        self._pending_failback_tip = None
                        switched = True
            if switched:
                LOG.warning("bitcoind RPC failed over to %s", redact_url(url))
            return body["result"]
        raise RPCConnectionError(f"all bitcoind endpoints unavailable: {last_error}")

    def getblocktemplate(self, rules=("segwit",), validate=None) -> dict:
        """Fetch a block template. `validate`, if given, must raise on unusable work; the failover
        endpoint is stuck only after it succeeds, so a backup serving bad templates can't pin it."""
        params = [{"rules": list(rules),
                   "capabilities": ["coinbasetxn", "workid", "coinbase/append"]}]
        payload = msgspec.json.encode(
            {
                "jsonrpc": "1.0",
                "id": self._next_request_id(),
                "method": "getblocktemplate",
                "params": params,
            }
        )
        count = len(self._endpoints)
        with self._state_lock:
            start = self._current
            pending_failback_tip = self._pending_failback_tip
            self._pending_failback_tip = None
        endpoint_indices = [(start + offset) % count for offset in range(count)]
        if pending_failback_tip is not None and start != 0:
            endpoint_indices.remove(0)
            endpoint_indices.insert(0, 0)
        last_error = None
        for index in endpoint_indices:
            is_failback_candidate = (
                pending_failback_tip is not None and index == 0 and start != 0
            )
            url, auth = self._endpoints[index]
            try:
                body = self._post(url, auth, payload)
            except RPCConnectionError as e:
                last_error = e
                continue
            if body.get("error"):
                response_error = RPCResponseError(body["error"])
                if (
                    not is_failback_candidate
                    and response_error.code not in ENDPOINT_UNAVAILABLE_RPC_CODES
                ):
                    raise response_error
                last_error = response_error
                continue
            result = body["result"]
            if (
                is_failback_candidate
                and (
                    not isinstance(result, dict)
                    or result.get("previousblockhash") != pending_failback_tip
                )
            ):
                last_error = RPCConnectionError(
                    "primary bitcoind returned work for an unexpected tip"
                )
                continue
            if validate is not None:
                try:
                    validate(result)
                except Exception as e:  # noqa: BLE001
                    last_error = e
                    continue
            switched = False
            if index != start:
                with self._state_lock:
                    if self._current == start:
                        self._current = index
                        switched = True
            if switched:
                if is_failback_candidate:
                    LOG.info("bitcoind RPC failed back to the primary %s", redact_url(url))
                else:
                    LOG.warning("bitcoind RPC failed over to %s", redact_url(url))
            return result
        raise RPCConnectionError(
            f"all bitcoind endpoints unavailable for mining work: {last_error}"
        )

    def submitblock(self, block_hex: str):
        """Returns None on acceptance, or bitcoind's rejection reason string."""
        return self.call("submitblock", [block_hex])

    def validateaddress(self, address: str) -> dict:
        return self.call("validateaddress", [address])

    def getblockcount(self) -> int:
        return self.call("getblockcount")

    def getblockchaininfo(self) -> dict:
        return self.call("getblockchaininfo")

    def maybe_failback(self, expected_tip: str) -> None:
        """Nominate a recovered primary for validation by the next template fetch."""
        if not expected_tip:
            return
        now = time.monotonic()
        with self._state_lock:
            if self._current == 0:
                return
            if now - self._last_failback_probe < FAILBACK_PROBE_SECONDS:
                return
            self._last_failback_probe = now
            active_index = self._current
        payload = msgspec.json.encode(
            {
                "jsonrpc": "1.0",
                "id": self._next_request_id(),
                "method": "getbestblockhash",
                "params": [],
            }
        )
        url, auth = self._endpoints[0]
        try:
            body = self._post(url, auth, payload)
        except RPCConnectionError:
            return
        if body.get("error") or body.get("result") != expected_tip:
            return
        with self._state_lock:
            if self._current == active_index:
                self._pending_failback_tip = expected_tip

    @property
    def active_index(self) -> int:
        """Index of the endpoint currently serving calls (0 = primary)."""
        with self._state_lock:
            return self._current

    def endpoint_urls(self) -> list[str]:
        """Resolved endpoint URLs in failover order (primary first)."""
        return [url for url, _auth in self._endpoints]

    def getbestblockhash(self) -> str:
        return self.call("getbestblockhash")

    def getblockheader(self, block_hash: str) -> dict:
        return self.call("getblockheader", [block_hash])
