"""Registration and ingest endpoints.

These are designed around one fact that shapes everything: **the server sits behind the
network being debugged.** During the outages this system exists to investigate, probes
cannot reach it. So ingest must treat delayed, duplicated, and out-of-order delivery as
the normal case rather than as errors.
"""

from __future__ import annotations

import sqlite3
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from netdbg_common.enums import ProbeStatus
from netdbg_common.models import (
    PROTOCOL_VERSION,
    Batch,
    IngestResponse,
    RegisterRequest,
    RegisterResponse,
)
from netdbg_common.timeutil import utc_now_ms
from netdbg_server.api.auth import generate_token, hash_token, require_probe
from netdbg_server.config import get_config
from netdbg_server.db.engine import transaction
from netdbg_server.db.queries import (
    insert_events,
    insert_samples,
    insert_wifi_samples,
    record_batch,
    touch_probe_seen,
    upsert_probe,
)

router = APIRouter(prefix="/api/v1", tags=["ingest"])


def _db(request: Request) -> sqlite3.Connection:
    conn: sqlite3.Connection = request.app.state.db
    return conn


@router.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest, request: Request) -> RegisterResponse:
    """Self-registration. A probe needs only the server address and a name.

    Re-registration with an existing ``probe_id`` (an agent restart) refreshes the
    probe's self-reported metadata and issues a fresh token. Admin-set fields --
    display name, group, location -- are preserved by ``upsert_probe``, so restarting an
    agent never undoes a rename made in the UI.
    """
    conn = _db(request)
    cfg = get_config()
    now = utc_now_ms()

    probe_id = req.probe_id or str(uuid.uuid4())
    token = generate_token()

    status_value = ProbeStatus.ACTIVE if cfg.auto_approve_probes else ProbeStatus.PENDING

    with transaction(conn):
        # Preserve an existing probe's status: an operator who retired a probe should
        # not have that undone by the agent simply restarting and re-registering.
        existing = conn.execute(
            "SELECT status FROM probes WHERE probe_id = ?", (probe_id,)
        ).fetchone()
        if existing is not None:
            status_value = ProbeStatus(existing["status"])

        upsert_probe(conn, probe_id, req.probe, now, status=status_value)
        conn.execute(
            "UPDATE probes SET auth_token_hash = ? WHERE probe_id = ?",
            (hash_token(token), probe_id),
        )

    return RegisterResponse(
        probe_id=probe_id,
        token=token,
        config_revision=cfg.config_revision,
    )


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest(
    batch: Batch,
    request: Request,
    probe_id: str = Depends(require_probe),
) -> IngestResponse:
    """Accept a batch of buffered measurements.

    Properties that matter, each for a concrete reason:

    * **Idempotent on ``batch_id``.** The agent retries across a flapping network and
      cannot know whether a request that timed out was actually applied. Replaying a
      batch is therefore routine, and must be a no-op rather than duplicate data.
    * **Old timestamps are accepted unconditionally.** A backfill after a six-hour
      outage carries six-hour-old measurements. Rejecting them would discard precisely
      the data the outage produced.
    * **``ts`` is never overridden.** The server records its own ``recv_ts`` alongside.
    * **Clock offset is measured, not corrected.** Rewriting agent timestamps toward
      server time would destroy the measurement's meaning; the offset is stored so
      correlation can weigh it later.
    """
    conn = _db(request)
    cfg = get_config()
    recv_ts = utc_now_ms()

    if batch.probe_id != probe_id:
        # The authenticated identity wins over the body's claim, so one probe cannot
        # write data attributed to another.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Batch probe_id does not match authenticated probe",
        )

    if batch.protocol_version != PROTOCOL_VERSION:
        # Loud failure beats silently dropping fields a newer agent sends.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Protocol version mismatch: agent sent {batch.protocol_version}, "
                f"server speaks {PROTOCOL_VERSION}"
            ),
        )

    total = len(batch.samples) + len(batch.wifi_samples)
    if total > cfg.max_batch_samples:
        # 413 rather than truncation: silently dropping the tail of a backfill would
        # lose data while reporting success.
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Batch of {total} exceeds limit of {cfg.max_batch_samples}; chunk it",
        )

    # Estimated skew, from the agent's send time against server receipt. Contaminated by
    # transit and queueing delay, so it is an estimate for confidence-weighting only --
    # never applied to correct `ts`.
    clock_offset_ms = batch.agent_ts - recv_ts

    with transaction(conn):
        if not record_batch(conn, batch.batch_id, probe_id, recv_ts, total):
            # Already applied. Report success so the agent stops retrying and drops it
            # from its spool -- an error here would make it retry forever.
            return IngestResponse(
                accepted=0,
                duplicate=True,
                server_ts=recv_ts,
                clock_offset_ms=clock_offset_ms,
                config_revision=cfg.config_revision,
            )

        accepted = insert_samples(conn, probe_id, list(batch.samples), recv_ts)
        accepted += insert_wifi_samples(conn, probe_id, list(batch.wifi_samples), recv_ts)
        insert_events(conn, probe_id, list(batch.events))

        # Server time, deliberately: this answers "when did we last hear from this
        # probe", which is what probe_silence detection needs. Agent time would make a
        # backfill of old samples look like a fresh check-in.
        touch_probe_seen(conn, probe_id, recv_ts, clock_offset_ms)

    return IngestResponse(
        accepted=accepted,
        duplicate=False,
        server_ts=recv_ts,
        clock_offset_ms=clock_offset_ms,
        config_revision=cfg.config_revision,
    )


@router.get("/health")
def health(request: Request) -> dict[str, object]:
    """Server liveness plus per-probe freshness.

    Probe freshness is included because a healthy server with silent probes is not a
    healthy system -- and that combination is itself diagnostic.
    """
    conn = _db(request)
    now = utc_now_ms()
    probes = conn.execute(
        "SELECT probe_id, name, display_name, last_seen_ts FROM probes WHERE status = 'active'"
    ).fetchall()

    return {
        "status": "ok",
        "server_ts": now,
        "protocol_version": PROTOCOL_VERSION,
        "probes": [
            {
                "probe_id": p["probe_id"],
                "name": p["display_name"] or p["name"],
                "last_seen_ts": p["last_seen_ts"],
                "stale_ms": None if p["last_seen_ts"] is None else now - p["last_seen_ts"],
            }
            for p in probes
        ],
    }
