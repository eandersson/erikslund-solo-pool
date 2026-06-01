"""HTTP API endpoints (plus a dashboard at /).

The stratifier/connector/generator stats are views over the single process.
"""

import logging

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.responses import PlainTextResponse

from erikslund_pool.constants import _API_ADDRESS_CHARS
from erikslund_pool.dashboard import render_dashboard
from erikslund_pool.metrics import render_prometheus

LOG = logging.getLogger(__name__)
ROUTER = APIRouter()


def _pool(request: Request):
    return request.app.state.pool


@ROUTER.get("/health", response_class=PlainTextResponse)
async def health(request: Request) -> PlainTextResponse:
    ok = _pool(request).health()
    return PlainTextResponse("ok\n" if ok else "degraded\n", status_code=200 if ok else 503)


@ROUTER.get("/status")
async def status(request: Request) -> dict:
    return _pool(request).status()


@ROUTER.get("/stats/pool")
async def stats_pool(request: Request) -> dict:
    return _pool(request).pool_stats()


@ROUTER.get("/stats/stratifier")
async def stats_stratifier(request: Request) -> dict:
    return _pool(request).stratifier_stats()


@ROUTER.get("/stats/connector")
async def stats_connector(request: Request) -> dict:
    return _pool(request).connector_stats()


@ROUTER.get("/stats/generator")
async def stats_generator(request: Request) -> dict:
    return _pool(request).generator_stats()


@ROUTER.get("/stats/client/{address}")
async def stats_client(request: Request, address: str) -> dict:
    if not address or len(address) > 127 or any(char not in _API_ADDRESS_CHARS for char in address):
        raise HTTPException(status_code=400, detail="invalid address")
    data = _pool(request).client_stats(address)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown address")
    return data


@ROUTER.get("/metrics", response_class=PlainTextResponse)
async def metrics(request: Request) -> PlainTextResponse:
    return PlainTextResponse(
        render_prometheus(_pool(request)),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@ROUTER.get("/metrics.json")
async def metrics_json(request: Request) -> dict:
    return _pool(request).metrics()


@ROUTER.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return HTMLResponse(render_dashboard(_pool(request)))
