#!/usr/bin/env python3
"""
fakebitcoind -- a stub bitcoind JSON-RPC node for testing erikslund-pool.

Stands in for a real bitcoind so the full pipeline runs without a real node:

    miner  --stratum-->  erikslund-pool  --JSON-RPC-->  fakebitcoind

Implements: validateaddress, getblocktemplate, getblockcount, getblockhash,
getbestblockhash, submitblock, preciousblock, and no-op stubs for
decoderawtransaction / sendrawtransaction / getrawtransaction.

Validates submitted blocks' proof-of-work only -- no tx/coinbase/signature
checks. Block changes are surfaced via getbestblockhash polling; an optional
ZMQ feed is available with --zmq (requires pyzmq).

USAGE
    python3 fakebitcoind.py                       # 127.0.0.1:8332, difficulty 1
    python3 fakebitcoind.py --difficulty 16       # ~1 block per 16 shares
    python3 fakebitcoind.py --network-interval 30 # also mint a block every 30s

    Matching pool.yml bitcoin_nodes entry:
        address: 127.0.0.1:8332
        username: user
        password: pass
"""

import argparse
import hashlib
import json
import logging
import socketserver
import struct
import threading
import time

try:
    import zmq
except ImportError:
    # pyzmq is optional: without it erikslund-pool still notices new blocks via
    # its getbestblockhash polling, and --zmq degrades to a warning.
    zmq = None

# Pool-difficulty-1 target (== miner's DIFF1_TARGET): 0x00000000FFFF0000...
DIFF1_TARGET = 0xFFFF << 208

LOG = logging.getLogger(__name__)


def difficulty_to_target(difficulty: float) -> int:
    """Network target for a given difficulty (lower difficulty => bigger target)."""
    if difficulty <= 0:
        return DIFF1_TARGET
    return min(int(DIFF1_TARGET / difficulty), (1 << 256) - 1)


def target_to_compact_bits(target: int) -> str:
    """Encode a 256-bit target as Bitcoin's compact 'nBits' form (8 hex chars)."""
    raw = target.to_bytes(32, "big").lstrip(b"\x00")
    if not raw:
        raw = b"\x00"
    # If the high bit of the top byte is set, prepend a zero so the sign bit
    # (which Bitcoin's compact form reserves) stays clear.
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    size = len(raw)
    mantissa = raw[:3]
    if size < 3:
        mantissa = mantissa + b"\x00" * (3 - size)
    compact = (size << 24) | int.from_bytes(mantissa, "big")
    return f"{compact:08x}"


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class FakeChain:
    """A minimal, in-memory chain the pool can build on top of."""

    def __init__(self, height: int, difficulty: float, reward_sats: int):
        self.lock = threading.Lock()
        self.height = height
        self.difficulty = difficulty
        self.target = difficulty_to_target(difficulty)
        self.bits = target_to_compact_bits(self.target)
        self.reward_sats = reward_sats
        self.version = 0x20000000
        seed = double_sha256(b"fakebitcoind tip @ height %d" % height)
        self.best_hash = seed[::-1].hex()
        self.by_height = {height: self.best_hash}
        self.curtime = int(time.time())
        self.blocks_accepted = 0
        self.blocks_rejected = 0

    def template(self) -> dict:
        """A getblocktemplate result for the current tip."""
        with self.lock:
            self.curtime = int(time.time())
            return {
                "version": self.version,
                "rules": [],
                "vbavailable": {},
                "vbrequired": 0,
                "previousblockhash": self.best_hash,
                "transactions": [],                # empty block: nothing to include
                "coinbaseaux": {"flags": ""},
                "coinbasevalue": self.reward_sats,
                "longpollid": self.best_hash + str(self.curtime),
                "target": f"{self.target:064x}",
                "mintime": self.curtime - 600,
                "mutable": ["time", "transactions", "prevblock"],
                "noncerange": "00000000ffffffff",
                "sigoplimit": 80000,
                "sizelimit": 4000000,
                "weightlimit": 4000000,
                "curtime": self.curtime,
                "bits": self.bits,
                "height": self.height + 1,
            }

    def submit_block(self, block_hex: str) -> str | None:
        """Validate a submitted block's PoW and, if good, extend the chain.

        Returns None on accept (bitcoind's success response) or a status
        string on rejection -- matching bitcoind's submitblock semantics.
        """
        try:
            header = bytes.fromhex(block_hex[:160])   # first 80 bytes
            if len(header) != 80:
                return "high-hash"
        except ValueError:
            return "rejected"

        block_hash = double_sha256(header)             # hash once, reuse below
        hash_int = int.from_bytes(block_hash, "little")
        with self.lock:
            target = self.target
        if hash_int > target:
            with self.lock:
                self.blocks_rejected += 1
            LOG.warning("submitblock rejected: block hash is above the target (insufficient proof-of-work)")
            return "high-hash"

        new_hash = block_hash[::-1].hex()              # same hash, display order
        with self.lock:
            self.height += 1
            self.best_hash = new_hash
            self.by_height[self.height] = new_hash
            self.blocks_accepted += 1
            height = self.height
        LOG.warning("block accepted at height %d: %s (the pool built a valid block)",
                    height, new_hash)
        return None

    def mint_network_block(self) -> None:
        """Simulate the rest of the network finding a block (advances the tip)."""
        with self.lock:
            self.curtime = int(time.time())
            filler = double_sha256(b"network block %d @ %d" % (self.height, self.curtime))
            self.height += 1
            self.best_hash = filler[::-1].hex()
            self.by_height[self.height] = self.best_hash
            height = self.height
        LOG.info("network mined a block; chain tip is now height %d", height)

    def best_block_hash(self) -> str:
        with self.lock:
            return self.best_hash

    def block_count(self) -> int:
        with self.lock:
            return self.height

    def block_hash_at(self, height: int) -> str | None:
        with self.lock:
            return self.by_height.get(height)


def validate_address(address: str) -> dict:
    """Accept any address; classify by prefix (P2PKH / P2SH / bech32) for coinbase assembly.

    Cryptographic verification is skipped -- PoW is the only acceptance criterion here.
    """
    is_segwit = address.startswith(("bc1", "tb1", "bcrt1"))
    is_script = address.startswith(("3", "2"))
    return {
        "isvalid": True,
        "address": address,
        "scriptPubKey": "",
        "isscript": is_script,
        "iswitness": is_segwit,
    }


class RpcServer:
    def __init__(self, chain: FakeChain, on_new_block=None):
        self.chain = chain
        self.on_new_block = on_new_block      # callback to fire ZMQ, etc.

    def handle(self, method: str, params: list) -> tuple[object, dict | None]:
        """Return (result, error). error is None on success."""
        match method:
            case "validateaddress":
                return validate_address(params[0] if params else ""), None
            case "getblocktemplate":
                return self.chain.template(), None
            case "getbestblockhash":
                return self.chain.best_block_hash(), None
            case "getblockcount":
                return self.chain.block_count(), None
            case "getblockhash":
                return self._getblockhash(params)
            case "submitblock":
                return self._submitblock(params)
            case "preciousblock":
                return None, None
            case "decoderawtransaction":
                return {"txid": "00" * 32, "vin": [], "vout": []}, None
            case "sendrawtransaction":
                return "00" * 32, None
            case "getrawtransaction":
                return "", None
            case _:
                LOG.debug("unimplemented RPC method '%s'; returning null", method)
                return None, None                 # be permissive: null, no error

    def _getblockhash(self, params: list) -> tuple[object, dict | None]:
        block_hash = self.chain.block_hash_at(int(params[0]))
        if block_hash is None:
            return None, {"code": -8, "message": "block height out of range"}
        return block_hash, None

    def _submitblock(self, params: list) -> tuple[object, dict | None]:
        before = self.chain.height
        result = self.chain.submit_block(params[0])
        if result is None and self.chain.height != before and self.on_new_block:
            self.on_new_block()
        return result, None


class RpcTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request_line = self.rfile.readline()
        if not request_line:
            return
        # Read headers until a blank line; tolerate both CRLF and LF.
        content_length = 0
        while True:
            line = self.rfile.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    content_length = int(value.strip())
                except ValueError:
                    content_length = 0
        body = self.rfile.read(content_length) if content_length else b""

        try:
            request = json.loads(body.decode() or "{}")
        except ValueError:
            self._respond({"result": None,
                           "error": {"code": -32700, "message": "parse error"},
                           "id": None})
            return

        method = request.get("method", "")
        params = request.get("params", []) or []
        request_id = request.get("id")
        try:
            result, error = self.server.rpc.handle(method, params)
        except Exception as exc:                  # never take the node down on one bad call
            LOG.exception("RPC method %s raised an exception", method)
            result, error = None, {"code": -1, "message": str(exc)}
        LOG.debug("RPC method %s returned %s", method, "an error" if error else "successfully")
        self._respond({"result": result, "error": error, "id": request_id})

    def _respond(self, payload: dict) -> None:
        # Trailing newline is required -- the pool reads line-by-line.
        body = json.dumps(payload).encode() + b"\n"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        self.wfile.write(response)


class RpcTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, rpc: RpcServer):
        super().__init__(address, RpcTCPHandler)
        self.rpc = rpc


class ZmqNotifier:
    """Publishes 'hashblock' on a ZMQ PUB socket (like bitcoind -zmqpubhashblock).

    Optional -- without it, the pool falls back to getbestblockhash polling.
    """

    def __init__(self, endpoint: str):
        if zmq is None:
            raise RuntimeError("pyzmq is not installed")
        self.ctx = zmq.Context.instance()
        self.sock = self.ctx.socket(zmq.PUB)
        self.sock.bind(endpoint)
        self.seq = 0
        LOG.info("ZMQ publishing hashblock notifications on %s", endpoint)

    def notify(self, chain: FakeChain) -> None:
        # "hashblock" topic: 32-byte hash (internal byte order) + 4-byte LE sequence.
        raw = bytes.fromhex(chain.best_block_hash())[::-1]
        self.sock.send_multipart([b"hashblock", raw, struct.pack("<I", self.seq)])
        self.seq += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fake bitcoind JSON-RPC node for testing erikslund-pool")
    parser.add_argument("--host", default="127.0.0.1", help="bind address")
    parser.add_argument("--rpcport", type=int, default=8332, help="JSON-RPC port")
    parser.add_argument("--difficulty", type=float, default=1.0,
                        help="network difficulty. 1 => every pool share is also a "
                             "block (full-path test); raise to make blocks rarer")
    parser.add_argument("--height", type=int, default=1, help="starting block height")
    parser.add_argument("--reward", type=int, default=5_000_000_000,
                        help="coinbasevalue in satoshis (default 50 BTC)")
    parser.add_argument("--network-interval", type=float, default=0.0,
                        help="also mint a network block every N seconds (0=off)")
    parser.add_argument("--zmq", default="",
                        help="ZMQ endpoint to publish hashblock on, e.g. "
                             "tcp://127.0.0.1:28332 (needs pyzmq; optional)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    chain = FakeChain(args.height, args.difficulty, args.reward)
    LOG.info("fake chain started: height %d, difficulty %g, bits %s, target %064x",
             chain.height, chain.difficulty, chain.bits, chain.target)
    if args.difficulty <= 1:
        LOG.info("difficulty <= 1: every accepted pool share will also be a block "
                 "(intentional -- it exercises the full submitblock path)")

    notifier = None
    if args.zmq:
        try:
            notifier = ZmqNotifier(args.zmq)
        except Exception as exc:
            LOG.warning("ZMQ disabled (%s); erikslund-pool will use block polling instead", exc)

    def on_new_block() -> None:
        if notifier:
            try:
                notifier.notify(chain)
            except Exception as exc:
                LOG.warning("ZMQ notification failed: %s", exc)

    rpc = RpcServer(chain, on_new_block=on_new_block)

    # Optional background "the network found a block" ticker.
    if args.network_interval > 0:
        def ticker() -> None:
            while True:
                time.sleep(args.network_interval)
                chain.mint_network_block()
                on_new_block()
        threading.Thread(target=ticker, daemon=True).start()
        LOG.info("minting a network block every %g seconds", args.network_interval)

    httpd = RpcTCPServer((args.host, args.rpcport), rpc)
    LOG.info("fakebitcoind JSON-RPC listening on http://%s:%d", args.host, args.rpcport)
    LOG.info("point pool.yml at: address: %s:%d  username: user  password: pass",
             args.host, args.rpcport)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutting down (accepted %d blocks, rejected %d)",
                 chain.blocks_accepted, chain.blocks_rejected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
