"""Server entry point and app factory."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from netdbg_server.api.ingest import router as ingest_router
from netdbg_server.config import ServerConfig, get_config
from netdbg_server.db.engine import init_db

__all__ = ["create_app", "main"]


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
        try:
            yield
        finally:
            app.state.db.close()

    app = FastAPI(
        title="netdbg",
        description="Distributed home network monitoring and diagnosis",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(ingest_router)
    return app


def main() -> None:
    import uvicorn

    cfg = get_config()
    uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port)


app = create_app


if __name__ == "__main__":
    main()
