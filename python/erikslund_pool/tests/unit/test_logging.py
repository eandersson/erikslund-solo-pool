"""Unit tests for the JSON log formatter and on-disk file logging."""

import json
import logging
import os
import tempfile
import unittest

from erikslund_pool.logging_config import JsonFormatter
from erikslund_pool.logging_config import configure_logging


def _format(**extra) -> dict:
    record = logging.LogRecord("erikslund_pool.x", logging.INFO, "path.py", 10,
                               "hello %s", ("world",), None)
    for key, value in extra.items():
        setattr(record, key, value)
    return json.loads(JsonFormatter().format(record))


class TestJsonFormatter(unittest.TestCase):
    def test_core_fields(self):
        payload = _format()
        self.assertEqual(payload["msg"], "hello world")
        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["logger"], "erikslund_pool.x")
        self.assertIn("ts", payload)

    def test_extra_keys_promoted(self):
        payload = _format(user_id="u1", count=3)
        self.assertEqual(payload["user_id"], "u1")
        self.assertEqual(payload["count"], 3)

    def test_underscore_keys_skipped(self):
        # Private/internal attrs must not leak into the log.
        self.assertNotIn("_internal", _format(_internal="x"))


class TestFileLogging(unittest.TestCase):
    """`LOG_FILE` adds a file handler alongside stderr (rotation is the OS's job)."""

    def setUp(self):
        # configure_logging() mutates the root logger and reads env; snapshot and
        # restore both so cases don't leak global state.
        root = logging.getLogger()
        saved_handlers, saved_level = root.handlers[:], root.level

        def _restore():
            for handler in root.handlers[:]:
                if isinstance(handler, logging.FileHandler):
                    handler.close()
            root.handlers[:] = saved_handlers
            root.setLevel(saved_level)
        self.addCleanup(_restore)

        env = os.environ.copy()
        self.addCleanup(lambda e=env: (os.environ.clear(), os.environ.update(e)))
        for var in ("LOG_FILE", "LOG_FORMAT", "LOG_LEVEL"):
            os.environ.pop(var, None)

    def test_writes_records_to_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "logs", "pool.log")  # nested dir auto-created
            os.environ["LOG_FILE"] = path
            configure_logging()
            logging.getLogger("erikslund_pool.test").warning("disk-line-%d", 7)

            root = logging.getLogger()
            file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
            # one file handler added; the stderr handler is kept
            self.assertEqual(len(file_handlers), 1)
            self.assertTrue(any(type(h) is logging.StreamHandler for h in root.handlers))
            for handler in root.handlers:
                handler.flush()
            with open(path, encoding="utf-8") as f:
                self.assertIn("disk-line-7", f.read())

    def test_bad_path_falls_back_to_stderr_without_raising(self):
        with tempfile.NamedTemporaryFile() as not_a_dir:
            # A path *under a regular file* can't be created -> OSError -> fallback.
            os.environ["LOG_FILE"] = os.path.join(not_a_dir.name, "sub", "pool.log")
            configure_logging()  # must not raise
            root = logging.getLogger()
            self.assertFalse(any(isinstance(h, logging.FileHandler) for h in root.handlers))
            self.assertTrue(any(type(h) is logging.StreamHandler for h in root.handlers))

    def test_no_file_handler_when_log_file_unset(self):
        configure_logging()
        root = logging.getLogger()
        self.assertFalse(any(isinstance(h, logging.FileHandler) for h in root.handlers))
