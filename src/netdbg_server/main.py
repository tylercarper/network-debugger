"""Server entry point and app factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from netdbg_common.timeutil import utc_now_ms
from netdbg_server.api.detect import router as detect_router
from netdbg_server.api.ingest import router as ingest_router
from netdbg_server.config import ServerConfig, get_config
from netdbg_server.db.engine import init_db
from netdbg_server.detect.engine import DetectionEngine

__all__ = ["create_app", "main"]

log = logging.getLogger("netdbg.server")


async def _detection_loop(app: FastAPI, interval_s: float) -> None:
    """Run detection over every probe on a fixed cadence.

    Detection is authoritative and server-side precisely because the agent is on the
    broken side of the network; running it here on a timer -- rather than inline on
    ingest -- keeps a slow detection pass from ever delaying a probe's report.
    """
    engine = DetectionEngine()
    while True:
        try:
            await asyncio.sleep(interval_s)
            # SQLite work is synchronous; hand it to a thread so the event loop (and thus
            # ingest) is never blocked by a detection pass over a large window.
            await asyncio.to_thread(engine.run_all, app.state.db, utc_now_ms())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("detection pass failed; will retry next interval")


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Build the app.

    Takes an optional config so tests can point at a temp database without touching
    process-wide state.
    """
    cfg = config or get_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        Path(cfg.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = init_db(cfg.db_path)
        # check_same_thread=False is safe here because SQLite serializes writes and
        # every write path goes through an explicit IMMEDIATE transaction.
        conn.close()
        app.state.db = sqlite3.connect(
            str(cfg.db_path), isolation_level=None, check_same_thread=False
        )
        app.state.db.row_factory = sqlite3.Row
        from netdbg_server.db.engine import apply_pragmas

        apply_pragmas(app.state.db)
        app.state.config = cfg

        detection_task: asyncio.Task[None] | None = None
        if cfg.detection_interval_s > 0:
            detection_task = asyncio.create_task(_detection_loop(app, cfg.detection_interval_s))
        try:
            yield
        finally:
            if detection_task is not None:
                detection_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await detection_task
            app.state.db.close()

    app = FastAPI(
        title="netdbg",
        description="Distributed home network monitoring and diagnosis",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(ingest_router)
    app.include_router(detect_router)
    return app


def main() -> None:
    import uvicorn

    cfg = get_config()
    uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port)


app = create_app


if __name__ == "__main__":
    main()
