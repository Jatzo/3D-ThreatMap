"""FastAPI app: streams attack events (simulated or replayed) over a WebSocket and serves the UI."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections import Counter, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from .models import AttackEvent
from .sources import EventSource, ReplaySource, SimulatorSource

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
RECENT_MAX = 200
logger = logging.getLogger(__name__)


class Hub:
    """Tracks connected WebSocket clients plus rolling stats about recent events."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.recent: deque[AttackEvent] = deque(maxlen=RECENT_MAX)
        self.by_country: Counter[str] = Counter()
        self.by_type: Counter[str] = Counter()
        self.total = 0

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    def record(self, event: AttackEvent) -> None:
        self.recent.append(event)
        self.by_country[event.src.country] += 1
        self.by_type[event.attack_type] += 1
        self.total += 1

    async def broadcast(self, event: AttackEvent) -> None:
        if not self.clients:
            return
        payload = event.model_dump_json()
        clients = list(self.clients)
        results = await asyncio.gather(
            *(ws.send_text(payload) for ws in clients), return_exceptions=True
        )
        for ws, result in zip(clients, results, strict=True):
            if isinstance(result, Exception):
                self.disconnect(ws)


def build_source(rate: float | None, seed: int | None) -> EventSource:
    """Pick the event source from TM_SOURCE. Any bad setting stops the server at start-up."""
    kind = os.getenv("TM_SOURCE", "sim")
    if kind == "sim":
        rate = rate if rate is not None else float(os.getenv("TM_RATE", "2.0"))
        if seed is None and os.getenv("TM_SEED"):
            seed = int(os.environ["TM_SEED"])
        return SimulatorSource(rate, seed)
    if kind == "replay":
        path = os.getenv("TM_REPLAY_FILE")
        if not path:
            raise ValueError(
                "TM_SOURCE=replay needs TM_REPLAY_FILE, the path of a file made by "
                "tools/convert_cyberlab.py."
            )
        return ReplaySource(Path(path), float(os.getenv("TM_REPLAY_SPEED", "1.0")))
    raise ValueError(f"TM_SOURCE must be 'sim' or 'replay', not {kind!r}.")


def create_app(
    rate: float | None = None, seed: int | None = None, source: EventSource | None = None
) -> FastAPI:
    source = source or build_source(rate, seed)
    hub = Hub()

    async def produce() -> None:
        try:
            async for event in source.stream():
                hub.record(event)
                await hub.broadcast(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Without this the task would end silently and the page would just go quiet.
            logger.exception("The event source stopped, so no more events will be sent.")
            raise

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(produce())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Threat Map", version="0.1.0", lifespan=lifespan)

    @app.get("/api/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "mode": source.mode,
            "clients": len(hub.clients),
            "events_total": hub.total,
        }

    @app.get("/api/stats")
    async def stats() -> dict:
        return {
            "events_total": hub.total,
            "top_countries": hub.by_country.most_common(10),
            "by_attack_type": dict(hub.by_type),
            "clients": len(hub.clients),
        }

    @app.get("/api/events/recent")
    async def recent(limit: int = Query(50, ge=1, le=RECENT_MAX)) -> list[AttackEvent]:
        return list(hub.recent)[-limit:][::-1]

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await hub.connect(ws)
        try:
            while True:
                await ws.receive_text()  # we only push; this just detects disconnects
        except WebSocketDisconnect:
            pass
        finally:
            hub.disconnect(ws)

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    return app


app = create_app()
