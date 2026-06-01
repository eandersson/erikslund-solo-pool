"""Logging setup, configured once per entry point by `configure_logging()`.

`LOG_FORMAT=json` emits one JSON object per record; anything else gives console lines.
Logs go to stderr; `LOG_FILE` (CLI `--log-file`) also appends to a file. Rotation is
left to the OS (e.g. logrotate) -- the handler only appends.
"""

import logging
import os
import sys

import msgspec

from erikslund_pool.constants import _RESERVED


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Promote structured context passed via `extra={...}`.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # enc_hook=str stringifies any non-JSON extra= value so logging never raises.
        return msgspec.json.encode(payload, enc_hook=str).decode()


def _build_formatter() -> logging.Formatter:
    """Pick the record format from LOG_FORMAT (`json`, else console)."""
    if os.environ.get("LOG_FORMAT", "console").lower() == "json":
        return JsonFormatter()
    return logging.Formatter(
        "[%(asctime)s.%(msecs)03d] %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _file_handler(path: str) -> logging.Handler | None:
    """An append handler for `path` (parent dirs created as needed), or None if it can't
    be opened -- a bad log path must never stop the pool, so warn and fall back to stderr."""
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        return logging.FileHandler(path, encoding="utf-8")
    except OSError as e:
        print(f"WARNING: cannot open log file {path!r}: {e}; logging to stderr only",
              file=sys.stderr)
        return None


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    formatter = _build_formatter()

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    # Optionally also append to a file (LOG_FILE / --log-file).
    log_file = os.environ.get("LOG_FILE")
    if log_file and (file_handler := _file_handler(log_file)) is not None:
        handlers.append(file_handler)

    for handler in handlers:
        handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.INFO))
