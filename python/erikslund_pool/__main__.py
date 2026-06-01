"""CLI entry: `python -m erikslund_pool [--config FILE] [overrides...]`."""

import argparse
import os

from erikslund_pool.config import SETTINGS
from erikslund_pool.config import Settings
from erikslund_pool.exceptions import ConfigError
from erikslund_pool.main import run


def main() -> None:
    parser = argparse.ArgumentParser(
        "erikslund_pool", description="Solo Bitcoin Stratum mining pool (FastAPI + asyncio)")
    parser.add_argument("-c", "--config", help="path to JSON config file")
    parser.add_argument("--rpc-url")
    parser.add_argument("--rpc-user")
    parser.add_argument("--rpc-password")
    parser.add_argument("--bind-host", help="stratum bind host")
    parser.add_argument("--bind-port", type=int, help="stratum bind port")
    parser.add_argument("--api-host", help="HTTP API bind host")
    parser.add_argument("--api-port", type=int, help="HTTP API bind port")
    parser.add_argument("--difficulty", type=float, help="starting share difficulty")
    parser.add_argument("--no-vardiff", action="store_true")
    parser.add_argument("--zmq-block", help="bitcoind zmqpubhashblock endpoint")
    parser.add_argument("--stats-dir", help="dir for pool.status / users stats files")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--log-format", choices=["console", "json"])
    parser.add_argument("--log-file",
                        help="also append logs to this file on disk "
                             "(rotation is left to the OS, e.g. logrotate)")
    args = parser.parse_args()

    # Set the logging env before run() configures logging.
    os.environ.setdefault("LOG_LEVEL", args.log_level)
    if args.log_format:
        os.environ["LOG_FORMAT"] = args.log_format
    if args.log_file:
        os.environ["LOG_FILE"] = args.log_file

    if args.config:
        try:
            SETTINGS.apply(Settings.load(args.config))
        except ConfigError as e:
            raise SystemExit(f"erikslund_pool: config error: {e}") from e
    for flag, field in [
        ("rpc_url", "rpc_url"), ("rpc_user", "rpc_user"), ("rpc_password", "rpc_password"),
        ("bind_host", "bind_host"), ("bind_port", "bind_port"),
        ("api_host", "api_host"), ("api_port", "api_port"),
        ("zmq_block", "zmq_block_endpoint"), ("stats_dir", "stats_directory"),
    ]:
        value = getattr(args, flag)
        if value is not None:
            setattr(SETTINGS, field, value)
    if args.difficulty is not None:
        SETTINGS.initial_difficulty = args.difficulty
    if args.no_vardiff:
        SETTINGS.variable_difficulty = False

    # Validate the effective config (file + CLI overrides) so a bad override fails fast.
    try:
        SETTINGS._validate()
    except ConfigError as e:
        raise SystemExit(f"erikslund_pool: config error: {e}") from e

    run()


if __name__ == "__main__":
    main()
