"""Dashboard and /series API tests.

These cover the server side of the dashboard -- the page is served, static assets load,
and /series returns correctly-shaped bucketed data. The visual behaviour is verified
separately by driving the real page in a browser.
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
    cfg = ServerConfig(db_path=tmp_path / "web.db", detection_interval_s=0)
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


def _feed(client: TestClient, probe: dict[str, str], target: str, oks: list[bool]) -> None:
    samples = [
        Sample(
            ts=NOW + i * 1000,
            kind=SampleKind.ICMP,
            target=target,
            success=ok,
            value_ms=5.0 if ok else None,
        )
        for i, ok in enumerate(oks)
    ]
    batch = Batch(
        probe_id=probe["probe_id"], batch_id=str(uuid.uuid4()), agent_ts=NOW, samples=samples
    )
    resp = client.post(
        "/api/v1/ingest",
        json=batch.model_dump(mode="json"),
        headers={"X-Probe-Id": probe["X-Probe-Id"], "Authorization": probe["Authorization"]},
    )
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# The page itself
# ---------------------------------------------------------------------------


def test_dashboard_page_is_served(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "netdbg" in resp.text
    assert "app.js" in resp.text, "page should reference its script"


def test_static_assets_load(client: TestClient) -> None:
    for asset in ("/static/app.js", "/static/app.css"):
        resp = client.get(asset)
        assert resp.status_code == 200, f"{asset} did not load"


def test_api_docs_still_available(client: TestClient) -> None:
    """The dashboard at / must not shadow the API docs."""
    assert client.get("/docs").status_code == 200


# ---------------------------------------------------------------------------
# /series
# ---------------------------------------------------------------------------


def test_series_returns_bucketed_shape(client: TestClient, probe: dict[str, str]) -> None:
    _feed(client, probe, "gateway", [True] * 60)

    resp = client.get(f"/api/v1/series?from_ts={NOW - 1000}&to_ts={NOW + 60_000}")
    assert resp.status_code == 200
    body = resp.json()

    assert body["series"], "should return at least one series"
    s = body["series"][0]
    # Parallel arrays, all the same length -- what the timeline plots directly.
    assert len(s["bucket_ts"]) == len(s["ok_rate"]) == len(s["avg_ms"]) == len(s["worst_ok"])
    assert s["target"] == "gateway"
    assert s["probe_id"] == probe["probe_id"]


def test_series_worst_ok_catches_a_short_outage_in_a_coarse_bucket(
    client: TestClient, probe: dict[str, str]
) -> None:
    """The bug found by looking at the real dashboard: a brief total outage inside a
    wide bucket averages to green and vanishes from the timeline.

    Feed a long healthy stretch with a short total-loss burst, request a window so wide
    that everything lands in ONE display bucket, and assert that while the average ok_rate
    stays high, worst_ok drops low enough to colour the ribbon as an outage.
    """
    # 20 min healthy, ~2 min total loss, 20 min healthy -- at one sample/sec. The outage
    # spans more than one 60s worst-case sub-bucket, so at least one sub-bucket is fully
    # dark regardless of phase alignment.
    oks = [True] * 1200 + [False] * 120 + [True] * 1200
    _feed(client, probe, "anchor-primary", oks)

    # A 7-day window forces a very coarse display bucket, so all of this is one bucket.
    body = client.get(f"/api/v1/series?from_ts={NOW}&to_ts={NOW + 7 * 86_400_000}").json()
    s = body["series"][0]

    avg = max(r for r in s["ok_rate"] if r is not None)
    worst = min(r for r in s["worst_ok"] if r is not None)

    assert avg > 0.9, "the average should stay high -- the outage is a small fraction"
    assert worst < 0.3, (
        f"worst_ok stayed at {worst}; a short total outage was averaged away and would "
        "be invisible on the timeline"
    )


def test_series_computes_success_rate(client: TestClient, probe: dict[str, str]) -> None:
    # 40 ok, 20 fail over one bucket -> ok_rate ~0.667 when bucketed coarsely.
    _feed(client, probe, "anchor-primary", [True] * 40 + [False] * 20)

    body = client.get(f"/api/v1/series?from_ts={NOW - 1000}&to_ts={NOW + 60_000}").json()
    rates = body["series"][0]["ok_rate"]
    overall = sum(r for r in rates if r is not None) / len([r for r in rates if r is not None])
    assert 0.5 < overall < 0.85, f"expected ~0.67 aggregate success, got {overall}"


def test_series_bucket_size_scales_with_window(client: TestClient, probe: dict[str, str]) -> None:
    """A wide window must use coarse buckets, so the point count stays bounded.

    Without this a 7-day view would try to ship millions of raw rows to the browser.
    """
    _feed(client, probe, "gateway", [True] * 60)

    narrow = client.get(f"/api/v1/series?from_ts={NOW}&to_ts={NOW + 60_000}").json()
    wide = client.get(f"/api/v1/series?from_ts={NOW}&to_ts={NOW + 7 * 86_400_000}").json()

    assert wide["bucket_ms"] > narrow["bucket_ms"], "wide window should bucket coarser"


def test_series_separates_targets(client: TestClient, probe: dict[str, str]) -> None:
    """Each (probe, target) is its own series -- the timeline merges them per probe,
    but the API keeps them distinct so a probe-detail view can show divergence."""
    _feed(client, probe, "gateway", [True] * 30)
    _feed(client, probe, "anchor-primary", [True] * 30)

    body = client.get(f"/api/v1/series?from_ts={NOW - 1000}&to_ts={NOW + 60_000}").json()
    targets = {s["target"] for s in body["series"]}
    assert targets == {"gateway", "anchor-primary"}


def test_series_empty_window(client: TestClient) -> None:
    body = client.get(f"/api/v1/series?from_ts={NOW}&to_ts={NOW + 1000}").json()
    assert body["series"] == []
