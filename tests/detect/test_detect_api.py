"""Detection API tests: the /events read path, /detect/rerun, and backfill-on-ingest.

These exercise detection through the running server, so they cover the wiring -- the
ingest hook that rewinds the watermark, and the rerun endpoint -- not just the engine in
isolation.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netdbg_common.enums import SampleKind
from netdbg_common.models import Batch, ProbeInfo, Sample
from netdbg_server.config import ServerConfig
from netdbg_server.main import create_app

NOW = 1_700_000_000_000


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    # detection_interval_s=0 disables the background loop; these tests drive detection
    # explicitly via the rerun endpoint for determinism.
    cfg = ServerConfig(db_path=tmp_path / "api.db", detection_interval_s=0)
    with TestClient(create_app(cfg)) as c:
        yield c


@pytest.fixture
def probe(client: TestClient) -> dict[str, str]:
    body = client.post(
        "/api/v1/register", json={"probe": ProbeInfo(name="p").model_dump(mode="json")}
    ).json()
    return {
        "probe_id": body["probe_id"],
        "X-Probe-Id": body["probe_id"],
        "Authorization": f"Bearer {body['token']}",
    }


def _headers(p: dict[str, str]) -> dict[str, str]:
    return {"X-Probe-Id": p["X-Probe-Id"], "Authorization": p["Authorization"]}


def _outage_batch(probe_id: str, start: int, count: int, ok: bool) -> dict[str, object]:
    samples = []
    for i in range(count):
        ts = start + i * 1000
        for target in ("gateway", "anchor-primary", "anchor-secondary"):
            samples.append(Sample(ts=ts, kind=SampleKind.ICMP, target=target, success=ok))
    return Batch(
        probe_id=probe_id, batch_id=str(uuid.uuid4()), agent_ts=NOW, samples=samples
    ).model_dump(mode="json")


def _ingest(client: TestClient, probe: dict[str, str], batch: dict[str, object]) -> None:
    resp = client.post("/api/v1/ingest", json=batch, headers=_headers(probe))
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# rerun + read
# ---------------------------------------------------------------------------


def test_rerun_detects_and_events_are_readable(client: TestClient, probe: dict[str, str]) -> None:
    pid = probe["probe_id"]
    _ingest(client, probe, _outage_batch(pid, NOW, 5, ok=True))
    _ingest(client, probe, _outage_batch(pid, NOW + 5000, 6, ok=False))
    _ingest(client, probe, _outage_batch(pid, NOW + 11000, 5, ok=True))

    rerun = client.post("/api/v1/admin/detect/rerun", json={"from_ts": NOW, "to_ts": NOW + 20000})
    assert rerun.status_code == 200
    assert rerun.json()["events_written"] >= 1

    events = client.get("/api/v1/events").json()["events"]
    assert any(e["event_type"] == "outage" for e in events)


def test_rerun_is_idempotent(client: TestClient, probe: dict[str, str]) -> None:
    """Replaying a rerun must not multiply events -- the property that makes it safe."""
    pid = probe["probe_id"]
    _ingest(client, probe, _outage_batch(pid, NOW, 5, ok=True))
    _ingest(client, probe, _outage_batch(pid, NOW + 5000, 6, ok=False))
    _ingest(client, probe, _outage_batch(pid, NOW + 11000, 5, ok=True))

    body = {"from_ts": NOW, "to_ts": NOW + 20000}
    client.post("/api/v1/admin/detect/rerun", json=body)
    first = len(client.get("/api/v1/events").json()["events"])
    client.post("/api/v1/admin/detect/rerun", json=body)
    second = len(client.get("/api/v1/events").json()["events"])

    assert first == second


def test_events_filter_by_type(client: TestClient, probe: dict[str, str]) -> None:
    pid = probe["probe_id"]
    _ingest(client, probe, _outage_batch(pid, NOW, 5, ok=True))
    _ingest(client, probe, _outage_batch(pid, NOW + 5000, 6, ok=False))
    _ingest(client, probe, _outage_batch(pid, NOW + 11000, 5, ok=True))
    client.post("/api/v1/admin/detect/rerun", json={"from_ts": NOW, "to_ts": NOW + 20000})

    outages = client.get("/api/v1/events", params={"event_type": "outage"}).json()["events"]
    assert outages and all(e["event_type"] == "outage" for e in outages)

    none = client.get("/api/v1/events", params={"event_type": "roam"}).json()["events"]
    assert none == []


# ---------------------------------------------------------------------------
# Backfill on ingest
# ---------------------------------------------------------------------------


def test_backfilled_outage_is_detected_after_rewind(
    client: TestClient, probe: dict[str, str]
) -> None:
    """The full wired path: healthy data detected, watermark advances, then buffered
    outage data arrives late and -- because ingest rewound the watermark -- is detected.
    """
    pid = probe["probe_id"]

    # Healthy window, detected, watermark moves past it.
    _ingest(client, probe, _outage_batch(pid, NOW, 5, ok=True))
    _ingest(client, probe, _outage_batch(pid, NOW + 15000, 5, ok=True))
    client.post("/api/v1/admin/detect/rerun", json={"from_ts": NOW, "to_ts": NOW + 20000})

    # Drive the watermark forward the way the live loop would.
    from netdbg_server.detect.engine import DetectionEngine

    db = client.app.state.db  # type: ignore[attr-defined]
    DetectionEngine().run_incremental(db, pid, NOW + 20000)

    assert not [
        e for e in client.get("/api/v1/events").json()["events"] if e["event_type"] == "outage"
    ]

    # Buffered outage arrives late (measured NOW+5000, delivered now). Ingest should
    # rewind the watermark.
    _ingest(client, probe, _outage_batch(pid, NOW + 5000, 6, ok=False))

    # The next incremental pass now re-covers the rewound window.
    DetectionEngine().run_incremental(db, pid, NOW + 30000)

    outages = [
        e for e in client.get("/api/v1/events").json()["events"] if e["event_type"] == "outage"
    ]
    assert outages, "backfilled outage not detected -- ingest did not rewind the watermark"
    assert outages[0]["started_ts"] == NOW + 5000
