"""Ingest and registration API tests.

The scenarios worth the most attention are the ones that only occur when the network is
broken -- which is exactly when this system has to work. Duplicate delivery, six-hour-old
backfill, and out-of-order arrival are the normal case here, not edge cases.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netdbg_common.enums import EventType, LinkType, SampleKind, Severity
from netdbg_common.models import Batch, Event, ProbeInfo, Sample, WifiSample
from netdbg_server.config import ServerConfig
from netdbg_server.main import create_app

NOW = 1_700_000_000_000


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    cfg = ServerConfig(db_path=tmp_path / "api.db")
    with TestClient(create_app(cfg)) as c:
        yield c


@pytest.fixture
def probe(client: TestClient) -> dict[str, str]:
    """A registered probe with its auth headers."""
    resp = client.post(
        "/api/v1/register",
        json={
            "probe": ProbeInfo(name="pi-wired", link_type=LinkType.WIRED).model_dump(mode="json")
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    return {
        "probe_id": body["probe_id"],
        "X-Probe-Id": body["probe_id"],
        "Authorization": f"Bearer {body['token']}",
    }


def _headers(probe: dict[str, str]) -> dict[str, str]:
    return {"X-Probe-Id": probe["X-Probe-Id"], "Authorization": probe["Authorization"]}


def _batch(
    probe_id: str,
    samples: list[Sample],
    *,
    batch_id: str | None = None,
    agent_ts: int = NOW,
) -> dict[str, object]:
    b = Batch(
        probe_id=probe_id,
        batch_id=batch_id or str(uuid.uuid4()),
        agent_ts=agent_ts,
        samples=samples,
    )
    return b.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_self_registration_issues_id_and_token(client: TestClient) -> None:
    """A probe needs only the server address and a name to join."""
    resp = client.post("/api/v1/register", json={"probe": {"name": "new-probe"}})

    assert resp.status_code == 200
    body = resp.json()
    assert body["probe_id"]
    assert body["token"]
    assert body["config_revision"] >= 1


def test_reregistration_keeps_probe_id_and_rotates_token(client: TestClient) -> None:
    """An agent restart re-registers with its stored id and gets a fresh token."""
    first = client.post("/api/v1/register", json={"probe": {"name": "p"}}).json()

    second = client.post(
        "/api/v1/register", json={"probe": {"name": "p"}, "probe_id": first["probe_id"]}
    ).json()

    assert second["probe_id"] == first["probe_id"]
    assert second["token"] != first["token"]


def test_reregistration_preserves_admin_rename(client: TestClient, probe: dict[str, str]) -> None:
    """Restarting an agent must not undo a rename made in the admin UI."""
    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    db.execute(
        "UPDATE probes SET display_name = 'Living Room Pi' WHERE probe_id = ?",
        (probe["probe_id"],),
    )

    client.post(
        "/api/v1/register", json={"probe": {"name": "pi-wired"}, "probe_id": probe["probe_id"]}
    )

    row = db.execute(
        "SELECT display_name FROM probes WHERE probe_id = ?", (probe["probe_id"],)
    ).fetchone()
    assert row["display_name"] == "Living Room Pi"


def test_reregistration_does_not_resurrect_retired_probe(
    client: TestClient, probe: dict[str, str]
) -> None:
    """An operator retired this probe; the agent restarting must not undo that."""
    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    db.execute("UPDATE probes SET status = 'retired' WHERE probe_id = ?", (probe["probe_id"],))

    client.post(
        "/api/v1/register", json={"probe": {"name": "pi-wired"}, "probe_id": probe["probe_id"]}
    )

    row = db.execute(
        "SELECT status FROM probes WHERE probe_id = ?", (probe["probe_id"],)
    ).fetchone()
    assert row["status"] == "retired"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_ingest_requires_token(client: TestClient, probe: dict[str, str]) -> None:
    resp = client.post(
        "/api/v1/ingest",
        json=_batch(probe["probe_id"], []),
        headers={"X-Probe-Id": probe["probe_id"]},
    )
    assert resp.status_code == 401


def test_ingest_rejects_wrong_token(client: TestClient, probe: dict[str, str]) -> None:
    resp = client.post(
        "/api/v1/ingest",
        json=_batch(probe["probe_id"], []),
        headers={"X-Probe-Id": probe["probe_id"], "Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_probe_cannot_write_data_attributed_to_another(
    client: TestClient, probe: dict[str, str]
) -> None:
    """The authenticated identity wins over the body's claim.

    Otherwise one misconfigured probe could corrupt another's timeline, and the
    cross-probe correlation that diagnoses scope would be reading fabricated data.
    """
    other = client.post("/api/v1/register", json={"probe": {"name": "other"}}).json()

    resp = client.post(
        "/api/v1/ingest",
        json=_batch(
            other["probe_id"], [Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True)]
        ),
        headers=_headers(probe),
    )
    assert resp.status_code == 403


def test_retired_probe_gets_distinct_error(client: TestClient, probe: dict[str, str]) -> None:
    """403 not 401: the token is fine, so the operator needs to know it is still running."""
    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    db.execute("UPDATE probes SET status = 'retired' WHERE probe_id = ?", (probe["probe_id"],))

    resp = client.post(
        "/api/v1/ingest", json=_batch(probe["probe_id"], []), headers=_headers(probe)
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Idempotency -- duplicate delivery is the normal case
# ---------------------------------------------------------------------------


def test_replaying_a_batch_is_a_verified_no_op(client: TestClient, probe: dict[str, str]) -> None:
    """The issue's explicit green-when condition.

    The agent retries across a flapping network and cannot know whether a timed-out
    request was applied. Replay must not duplicate data.
    """
    payload = _batch(
        probe["probe_id"],
        [
            Sample(ts=NOW + i, kind=SampleKind.ICMP, target="1.1.1.1", success=True, value_ms=10.0)
            for i in range(5)
        ],
    )

    first = client.post("/api/v1/ingest", json=payload, headers=_headers(probe))
    assert first.status_code == 202
    assert first.json()["accepted"] == 5
    assert first.json()["duplicate"] is False

    second = client.post("/api/v1/ingest", json=payload, headers=_headers(probe))
    assert second.status_code == 202, "replay must succeed, or the agent retries forever"
    assert second.json()["duplicate"] is True
    assert second.json()["accepted"] == 0

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 5


def test_duplicate_reports_success_so_agent_can_drop_it(
    client: TestClient, probe: dict[str, str]
) -> None:
    """A duplicate must not be an error status.

    If replay returned 4xx/5xx the agent would keep the batch spooled and retry it
    forever, and the spool would grow without bound.
    """
    payload = _batch(
        probe["probe_id"], [Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True)]
    )
    client.post("/api/v1/ingest", json=payload, headers=_headers(probe))
    resp = client.post("/api/v1/ingest", json=payload, headers=_headers(probe))

    assert 200 <= resp.status_code < 300


# ---------------------------------------------------------------------------
# Backfill -- the case that only happens when the network is broken
# ---------------------------------------------------------------------------


def test_six_hour_old_backfill_is_accepted_unmodified(
    client: TestClient, probe: dict[str, str]
) -> None:
    """The defining scenario: an outage ends and the probe ships what it buffered.

    Rejecting or rewriting these timestamps would discard exactly the data the outage
    produced -- and would place the outage at the moment connectivity *returned* rather
    than when it broke.
    """
    measured_at = NOW - 6 * 3_600_000

    resp = client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"],
            [
                Sample(
                    ts=measured_at + i * 1000, kind=SampleKind.ICMP, target="1.1.1.1", success=False
                )
                for i in range(10)
            ],
            agent_ts=NOW,
        ),
        headers=_headers(probe),
    )

    assert resp.status_code == 202
    assert resp.json()["accepted"] == 10

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    row = db.execute("SELECT MIN(ts) AS first_ts, MIN(recv_ts) AS recv FROM samples").fetchone()
    assert row["first_ts"] == measured_at, "backfilled ts was modified"
    assert row["recv"] > row["first_ts"], "recv_ts should record actual arrival"


def test_recv_ts_gap_records_outage_duration(client: TestClient, probe: dict[str, str]) -> None:
    """recv_ts - ts is itself a signal: how long the probe->server path was broken."""
    measured_at = NOW - 2 * 3_600_000
    client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"],
            [Sample(ts=measured_at, kind=SampleKind.ICMP, target="gw", success=False)],
        ),
        headers=_headers(probe),
    )

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    gap = db.execute("SELECT recv_ts - ts AS gap FROM samples").fetchone()["gap"]
    assert gap > 3_600_000, "gap should reflect the delay, not be zeroed out"


def test_out_of_order_batches_accepted(client: TestClient, probe: dict[str, str]) -> None:
    """Backfill interleaves with live data; arrival order is not measurement order."""
    client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"], [Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True)]
        ),
        headers=_headers(probe),
    )
    resp = client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"],
            [Sample(ts=NOW - 60_000, kind=SampleKind.ICMP, target="gw", success=False)],
        ),
        headers=_headers(probe),
    )

    assert resp.status_code == 202
    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    assert [r["ts"] for r in db.execute("SELECT ts FROM samples ORDER BY ts")] == [
        NOW - 60_000,
        NOW,
    ]


def test_clock_offset_is_reported_not_applied(client: TestClient, probe: dict[str, str]) -> None:
    """Skew is measured for confidence-weighting; it must never rewrite ts.

    Correcting agent timestamps toward server time would destroy the measurement's
    meaning -- the agent's clock is the only thing that knows when it measured.
    """
    skewed_agent_ts = NOW + 45_000
    measured_at = NOW

    resp = client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"],
            [Sample(ts=measured_at, kind=SampleKind.ICMP, target="gw", success=True)],
            agent_ts=skewed_agent_ts,
        ),
        headers=_headers(probe),
    )

    assert resp.json()["clock_offset_ms"] != 0, "skew should be measured"

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    assert db.execute("SELECT ts FROM samples").fetchone()["ts"] == measured_at


# ---------------------------------------------------------------------------
# Limits and validation
# ---------------------------------------------------------------------------


def test_oversized_batch_rejected_with_413(client: TestClient, probe: dict[str, str]) -> None:
    """413 rather than truncation.

    Silently dropping the tail of a backfill would lose data while reporting success --
    the worst possible outcome for a system whose job is not losing data.
    """
    cfg = ServerConfig()
    resp = client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"],
            [
                Sample(ts=NOW + i, kind=SampleKind.ICMP, target="gw", success=True)
                for i in range(cfg.max_batch_samples + 1)
            ],
        ),
        headers=_headers(probe),
    )

    assert resp.status_code == 413

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 0, "partial write on reject"


def test_protocol_version_mismatch_rejected(client: TestClient, probe: dict[str, str]) -> None:
    """Loud failure beats silently dropping fields a newer agent sends."""
    payload = _batch(probe["probe_id"], [])
    payload["protocol_version"] = 999

    resp = client.post("/api/v1/ingest", json=payload, headers=_headers(probe))
    assert resp.status_code == 400
    assert "version" in resp.json()["detail"].lower()


def test_unknown_field_rejected(client: TestClient, probe: dict[str, str]) -> None:
    payload = _batch(probe["probe_id"], [])
    payload["surprise_field"] = "from the future"

    resp = client.post("/api/v1/ingest", json=payload, headers=_headers(probe))
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Mixed payloads
# ---------------------------------------------------------------------------


def test_wifi_samples_and_events_ingested(client: TestClient, probe: dict[str, str]) -> None:
    """A real batch carries measurements, radio telemetry, and agent-side events."""
    batch = Batch(
        probe_id=probe["probe_id"],
        batch_id=str(uuid.uuid4()),
        agent_ts=NOW,
        samples=[Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True, value_ms=2.1)],
        wifi_samples=[
            WifiSample(
                ts=NOW,
                ssid="TestNet-5G",
                bssid="02:00:00:00:00:01",
                rssi_dbm=-58,
                channel=149,
                band="5GHz",
                source="iw",
            )
        ],
        events=[
            Event(
                event_type=EventType.CLOCK_STEP,
                severity=Severity.INFO,
                confidence=1.0,
                started_ts=NOW,
                evidence={"delta_ms": 3600000, "likely_suspend": True},
            )
        ],
    )

    resp = client.post(
        "/api/v1/ingest", json=batch.model_dump(mode="json"), headers=_headers(probe)
    )

    assert resp.status_code == 202
    assert resp.json()["accepted"] == 2  # samples + wifi_samples

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    assert db.execute("SELECT COUNT(*) FROM wifi_samples").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_clock_step_event_survives_roundtrip(client: TestClient, probe: dict[str, str]) -> None:
    """clock_step is agent-only -- the server cannot observe a probe's local clock jump.

    It is what lets detection suppress the phantom outage a sleeping laptop would
    otherwise report.
    """
    batch = Batch(
        probe_id=probe["probe_id"],
        batch_id=str(uuid.uuid4()),
        agent_ts=NOW,
        events=[
            Event(
                event_type=EventType.CLOCK_STEP,
                severity=Severity.INFO,
                confidence=1.0,
                started_ts=NOW,
                evidence={"delta_ms": 3_600_000, "likely_suspend": True},
            )
        ],
    )
    client.post("/api/v1/ingest", json=batch.model_dump(mode="json"), headers=_headers(probe))

    db: sqlite3.Connection = client.app.state.db  # type: ignore[attr-defined]
    row = db.execute("SELECT event_type, evidence FROM events").fetchone()
    assert row["event_type"] == "clock_step"
    assert "likely_suspend" in row["evidence"]


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_reports_probe_staleness(client: TestClient, probe: dict[str, str]) -> None:
    """A healthy server with silent probes is not a healthy system."""
    client.post(
        "/api/v1/ingest",
        json=_batch(
            probe["probe_id"], [Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True)]
        ),
        headers=_headers(probe),
    )

    body = client.get("/api/v1/health").json()

    assert body["status"] == "ok"
    assert len(body["probes"]) == 1
    assert body["probes"][0]["stale_ms"] is not None


def test_health_shows_never_seen_probe(client: TestClient, probe: dict[str, str]) -> None:
    """A registered probe that has never reported is a distinct, visible state."""
    body = client.get("/api/v1/health").json()
    assert body["probes"][0]["stale_ms"] is None
