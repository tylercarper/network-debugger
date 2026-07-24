"""Detection admin and query endpoints.

``/detect/rerun`` is what makes iterating on rules cheap: when a rule is improved, replay
it over any historical window and the events update in place. It is idempotent -- the same
rerun produces the same events -- so it is safe to invoke repeatedly.
"""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Request
from pydantic import BaseModel

from netdbg_common.timeutil import utc_now_ms
from netdbg_server.detect.correlate import Correlator
from netdbg_server.detect.engine import DetectionEngine

router = APIRouter(prefix="/api/v1", tags=["detection"])


def _db(request: Request) -> sqlite3.Connection:
    conn: sqlite3.Connection = request.app.state.db
    return conn


class RerunRequest(BaseModel):
    probe_id: str | None = None
    from_ts: int
    to_ts: int


class RerunResponse(BaseModel):
    probes: int
    events_written: int
    incidents: int


@router.post("/admin/detect/rerun", response_model=RerunResponse)
def rerun(req: RerunRequest, request: Request) -> RerunResponse:
    """Re-run detection *and* correlation over an explicit window.

    This does **not** touch the watermark: it is an out-of-band replay for one range, not
    a change to how far live detection has progressed. Both events and incidents upsert,
    so a replay refines rather than duplicates. Correlation runs after detection so it
    groups the events this replay just (re)produced.
    """
    conn = _db(request)
    engine = DetectionEngine()

    if req.probe_id is not None:
        probe_ids = [req.probe_id]
    else:
        probe_ids = [
            r["probe_id"]
            for r in conn.execute("SELECT probe_id FROM probes WHERE status = 'active'")
        ]

    total = 0
    for pid in probe_ids:
        total += engine.run_probe(conn, pid, req.from_ts, req.to_ts).events_written

    incidents = Correlator().correlate(conn, req.from_ts, req.to_ts)

    return RerunResponse(probes=len(probe_ids), events_written=total, incidents=len(incidents))


@router.get("/incidents")
def list_incidents(
    request: Request,
    from_ts: int | None = None,
    to_ts: int | None = None,
    scope: str | None = None,
    limit: int = 200,
) -> dict[str, object]:
    """Read correlated incidents -- the system's headline output.

    Each incident already carries its scope classification and hypothesis, so a caller
    (dashboard or agent) gets the diagnosis directly rather than reconstructing it.
    """
    conn = _db(request)
    clauses = ["1=1"]
    params: list[object] = []
    if from_ts is not None:
        clauses.append("started_ts >= ?")
        params.append(from_ts)
    if to_ts is not None:
        clauses.append("started_ts <= ?")
        params.append(to_ts)
    if scope is not None:
        clauses.append("scope = ?")
        params.append(scope)
    params.append(min(limit, 1000))

    rows = conn.execute(
        f"SELECT * FROM incidents WHERE {' AND '.join(clauses)} ORDER BY started_ts DESC LIMIT ?",
        params,
    ).fetchall()

    return {"incidents": [dict(r) for r in rows], "server_ts": utc_now_ms()}


@router.get("/events")
def list_events(
    request: Request,
    from_ts: int | None = None,
    to_ts: int | None = None,
    probe_id: str | None = None,
    event_type: str | None = None,
    limit: int = 500,
) -> dict[str, object]:
    """Read detected events for the dashboard and the analysis surface."""
    conn = _db(request)
    clauses = ["1=1"]
    params: list[object] = []
    if from_ts is not None:
        clauses.append("started_ts >= ?")
        params.append(from_ts)
    if to_ts is not None:
        clauses.append("started_ts <= ?")
        params.append(to_ts)
    if probe_id is not None:
        clauses.append("probe_id = ?")
        params.append(probe_id)
    if event_type is not None:
        clauses.append("event_type = ?")
        params.append(event_type)

    params.append(min(limit, 2000))
    rows = conn.execute(
        f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY started_ts DESC LIMIT ?",
        params,
    ).fetchall()

    return {
        "events": [dict(r) for r in rows],
        "server_ts": utc_now_ms(),
    }
