"""FastAPI application: the HTTP API + operator dashboard.

The Pool is started/stopped by the app lifespan, sharing uvicorn's event loop.
"""

import contextlib
import logging
import resource
from collections.abc import AsyncIterator

import uvicorn
from fastapi import FastAPI

from erikslund_pool import __version__
from erikslund_pool.config import SETTINGS
from erikslund_pool.logging_config import configure_logging
from erikslund_pool.pool import Pool
from erikslund_pool.routers import stats as stats_router
from erikslund_pool.util import redact_url

LOG = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    pool = Pool(SETTINGS)
    await pool.start()
    app.state.pool = pool
    try:
        yield
    finally:
        await pool.stop()


APP = FastAPI(
    title="erikslund-solo-pool",
    version=__version__,
    lifespan=lifespan,
)
APP.include_router(stats_router.ROUTER)


def run() -> None:
    """Entry point for the `erikslund_pool` console script and `python -m erikslund_pool`."""
    configure_logging()
    LOG.info("erikslund-solo-pool v%s starting -- stratum %s:%d, bitcoind %s",
             __version__, SETTINGS.bind_host, SETTINGS.bind_port, redact_url(SETTINGS.rpc_url))
    soft_fd_limit, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_fd_limit != resource.RLIM_INFINITY and SETTINGS.max_clients > soft_fd_limit:
        LOG.warning("max_clients (%d) exceeds the open file limit (%d); lowering to %d "
                    "-- raise it (ulimit -n / LimitNOFILE) to allow more",
                    SETTINGS.max_clients, soft_fd_limit, soft_fd_limit)
        SETTINGS.max_clients = soft_fd_limit
    fd_limit = "unlimited" if soft_fd_limit == resource.RLIM_INFINITY else str(soft_fd_limit)
    LOG.info("Max clients: %d (open file limit of %s)", SETTINGS.max_clients, fd_limit)
    LOG.info("HTTP API listening on %s:%d (/metrics, /status, /stats/*)",
             SETTINGS.api_host, SETTINGS.api_port)
    uvicorn.run(APP, host=SETTINGS.api_host, port=SETTINGS.api_port,
                log_config=None, access_log=False)
