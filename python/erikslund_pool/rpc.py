"""Minimal synchronous bitcoind JSON-RPC client with failover.

Calls are blocking; the pool runs them off the event loop via asyncio.to_thread.
A connection failure advances to the next endpoint and sticks there; an RPC
*error* (the node answered) does not fail over.
"""

import base64
import logging
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


class BitcoindRPC:
    def __init__(self, url, user, password, timeout=30.0, failover=None):
        # `failover`: optional (url, user, password) endpoints tried after the primary.
        endpoints = [(url, user, password)] + list(failover or [])
        self._endpoints = [self._resolve(endpoint_url, endpoint_user, endpoint_password)
                           for (endpoint_url, endpoint_user, endpoint_password) in endpoints]
        self.url = self._endpoints[0][0]  # resolved primary URL; read by tests
        self.timeout = timeout
        self._current = 0
        self._id = 0
        self._last_failback_probe = float("-inf")

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
            # bitcoind returns HTTP 500 + JSON error body for RPC errors; node is up, not a failover.
            try:
                return msgspec.json.decode(e.read())
            except Exception as parse_error:
                raise RPCConnectionError(f"HTTP {e.code} from bitcoind: {e.reason}") from parse_error
        except (urllib.error.URLError, OSError, ValueError) as e:
            # redact_url so embedded credentials don't reach the log.
            raise RPCConnectionError(f"bitcoind RPC failed at {redact_url(url)}: {e}") from e

    def call(self, method, params=None):
        self._id += 1
        payload = msgspec.json.encode(
            {"jsonrpc": "1.0", "id": self._id, "method": method, "params": params or []})
        count = len(self._endpoints)
        start = self._current
        last_error = None
        for i in range(count):
            index = (start + i) % count
            url, auth = self._endpoints[index]
            try:
                body = self._post(url, auth, payload)
            except RPCConnectionError as e:
                last_error = e
                continue
            # A node answering with a JSON-RPC error is up but unhealthy: raise without sticking the
            # failover, so the next call retries from the primary rather than pinning this endpoint.
            if body.get("error"):
                raise RPCResponseError(body["error"])
            if index != start and self._current == start:
                self._current = index
                LOG.warning("bitcoind RPC failed over to %s", redact_url(url))
            return body["result"]
        raise RPCConnectionError(f"all bitcoind endpoints unreachable: {last_error}")

    def getblocktemplate(self, rules=("segwit",), validate=None) -> dict:
        """Fetch a block template. `validate`, if given, must raise on unusable work; the failover
        endpoint is stuck only after it succeeds, so a backup serving bad templates can't pin it."""
        params = [{"rules": list(rules),
                   "capabilities": ["coinbasetxn", "workid", "coinbase/append"]}]
        if validate is None:
            return self.call("getblocktemplate", params)
        self._id += 1
        payload = msgspec.json.encode(
            {"jsonrpc": "1.0", "id": self._id, "method": "getblocktemplate", "params": params})
        count = len(self._endpoints)
        start = self._current
        last_error = None
        for i in range(count):
            index = (start + i) % count
            url, auth = self._endpoints[index]
            try:
                body = self._post(url, auth, payload)
            except RPCConnectionError as e:
                last_error = e
                continue
            if body.get("error"):
                raise RPCResponseError(body["error"])  # answered with an error -> don't stick
            result = body["result"]
            try:
                validate(result)
            except Exception as e:
                # Unusable work: treat like an unreachable endpoint -- try the next, don't stick here.
                last_error = e
                continue
            if index != start and self._current == start:
                self._current = index
                LOG.warning("bitcoind RPC failed over to %s", redact_url(url))
            return result
        raise RPCConnectionError(f"all bitcoind endpoints unreachable: {last_error}")

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
        """Switch back to the primary only when its getbestblockhash returns `expected_tip` (the
        tip the pool mines on) -- requiring the tip, not mere reachability, avoids failing back to
        a warming/catching-up node. Call off the latency path (can block up to the RPC timeout)."""
        if self._current == 0 or not expected_tip:
            return  # already on the primary / nothing to compare yet
        now = time.monotonic()
        if now - self._last_failback_probe < FAILBACK_PROBE_SECONDS:
            return
        self._last_failback_probe = now
        self._id += 1
        payload = msgspec.json.encode(
            {"jsonrpc": "1.0", "id": self._id, "method": "getbestblockhash", "params": []})
        url, auth = self._endpoints[0]
        try:
            body = self._post(url, auth, payload)
        except RPCConnectionError:
            return  # primary still down; stay on the backup
        if body.get("error") or body.get("result") != expected_tip:
            return  # warming up, errored, or on a different (behind/forked) tip
        self._current = 0
        LOG.info("bitcoind RPC failed back to the primary %s", redact_url(url))

    @property
    def active_index(self) -> int:
        """Index of the endpoint currently serving calls (0 = primary)."""
        return self._current

    def endpoint_urls(self) -> list[str]:
        """Resolved endpoint URLs in failover order (primary first)."""
        return [url for url, _auth in self._endpoints]

    def getbestblockhash(self) -> str:
        return self.call("getbestblockhash")

    def getblockheader(self, block_hash: str) -> dict:
        return self.call("getblockheader", [block_hash])
