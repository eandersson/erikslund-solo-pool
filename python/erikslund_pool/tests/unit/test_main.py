"""Unit tests for the FastAPI app wiring, lifespan, and run() entry point."""

import unittest
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

from erikslund_pool import main


class TestApp(unittest.TestCase):
    def test_app_metadata(self):
        self.assertEqual(main.APP.title, "erikslund-solo-pool")
        # Stats router plus FastAPI's default routes.
        self.assertGreater(len(main.APP.routes), 4)

    def test_run_invokes_uvicorn_with_settings(self):
        with (
            patch("erikslund_pool.main.configure_logging"),
            patch("erikslund_pool.main.uvicorn.run") as mock_run,
        ):
            main.run()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args.kwargs
        self.assertEqual(kwargs["host"], main.SETTINGS.api_host)
        self.assertEqual(kwargs["port"], main.SETTINGS.api_port)

    def test_run_logs_version_and_max_clients(self):
        with (
            patch("erikslund_pool.main.configure_logging"),
            patch("erikslund_pool.main.uvicorn.run"),
            self.assertLogs("erikslund_pool.main", level="INFO") as logs,
        ):
            main.run()
        joined = "\n".join(logs.output)
        self.assertIn(f"v{main.__version__} starting", joined)
        # max_clients may be clamped to the fd limit.
        self.assertRegex(joined, r"Max clients: \d+ \(open file limit of (\d+|unlimited)\)")


class TestLifespan(unittest.IsolatedAsyncioTestCase):
    async def test_lifespan_starts_then_stops_pool(self):
        fake_pool = MagicMock()
        fake_pool.start = AsyncMock()
        fake_pool.stop = AsyncMock()
        app = MagicMock()
        with patch("erikslund_pool.main.Pool", return_value=fake_pool):
            async with main.lifespan(app):
                fake_pool.start.assert_awaited_once()
                self.assertIs(app.state.pool, fake_pool)
        fake_pool.stop.assert_awaited_once()
