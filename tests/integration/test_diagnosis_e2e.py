"""End-to-end diagnosis: inject a known fault, assert the correct verdict.

Every other test checks that a *component* behaves. This one checks the product thesis:
given a fault of a known shape, does the whole vertical -- ingest, detection, correlation,
scope classification -- arrive at the right diagnosis? If it labels a backbone outage as
"one AP" or vice versa, the system fails at its single job, and no component test would
catch it because each component was individually correct.

The faults are injected as *ground truth* the test controls: a real multi-probe topology
in a real server, fed sample streams that encode a specific real-world failure. Then the
test asserts the emitted incident scope matches the fault that was injected.

A real HTTP server on a socket is used so ingest, the DB, detection, and correlation all
run exactly as in production -- only the sample *source* is synthetic, because injecting a
controlled fault is the entire point.
"""

from __future__ import annotations

import socket
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import uvicorn

from netdbg_common.enums import LinkType, SampleKind
from netdbg_common.models import Batch, ProbeInfo, Sample
from netdbg_server.config import ServerConfig
from netdbg_server.main import create_app

NOW = 1_700_000_000_000
TICK_MS = 1000


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class Probe:
    name: str
    link: LinkType
    group: str
    probe_id: str = ""
    token: str = ""


@dataclass
class Harness:
    url: str
    db_path: Path

    def register(self, probe: Probe) -> None:
        resp = httpx.post(
            f"{self.url}/api/v1/register",
            json={
                "probe": ProbeInfo(name=probe.name, link_type=probe.link).model_dump(mode="json")
            },
        )
        resp.raise_for_status()
        body = resp.json()
        probe.probe_id = body["probe_id"]
        probe.token = body["token"]
        # Set the group directly -- the admin rename flow is out of scope here.
        import sqlite3

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE probes SET group_name = ? WHERE probe_id = ?", (probe.group, probe.probe_id)
        )
        conn.commit()
        conn.close()

    def feed(self, probe: Probe, targets_ok: dict[str, list[bool]]) -> None:
        """Ship one sample per target per tick.

        ``targets_ok`` maps a target label to a per-tick success list; all lists must be
        the same length. This is how a fault is injected: e.g. gateway all-True while both
        anchors go False encodes gateway-up-internet-down.
        """
        length = len(next(iter(targets_ok.values())))
        samples: list[Sample] = []
        for i in range(length):
            ts = NOW + i * TICK_MS
            for target, oks in targets_ok.items():
                samples.append(
                    Sample(
                        ts=ts,
                        kind=SampleKind.ICMP,
                        target=target,
                        success=oks[i],
                        value_ms=5.0 if oks[i] else None,
                    )
                )
        batch = Batch(
            probe_id=probe.probe_id, batch_id=str(uuid.uuid4()), agent_ts=NOW, samples=samples
        )
        resp = httpx.post(
            f"{self.url}/api/v1/ingest",
            json=batch.model_dump(mode="json"),
            headers={"X-Probe-Id": probe.probe_id, "Authorization": f"Bearer {probe.token}"},
        )
        resp.raise_for_status()

    def diagnose(self, from_ts: int, to_ts: int) -> list[dict[str, object]]:
        """Run detection + correlation over the window and return the incidents."""
        httpx.post(
            f"{self.url}/api/v1/admin/detect/rerun",
            json={"from_ts": from_ts, "to_ts": to_ts},
            timeout=30,
        ).raise_for_status()
        resp = httpx.get(f"{self.url}/api/v1/incidents", timeout=30)
        resp.raise_for_status()
        incidents: list[dict[str, object]] = resp.json()["incidents"]
        return incidents


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    db_path = tmp_path / "e2e.db"
    # detection_interval_s=0 so nothing runs on a timer -- the test drives detection and
    # correlation explicitly, for determinism.
    cfg = ServerConfig(db_path=db_path, detection_interval_s=0)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(cfg), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("test server did not start")
    try:
        yield Harness(url=f"http://127.0.0.1:{port}", db_path=db_path)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _ok(n: int) -> list[bool]:
    return [True] * n


def _outage(n: int, start: int, end: int) -> list[bool]:
    """All-True except a fail stretch on [start, end)."""
    return [not (start <= i < end) for i in range(n)]


# Standard home topology under test.
def _probes() -> list[Probe]:
    return [
        Probe("pi-wired", LinkType.WIRED, "wired"),
        Probe("desktop-wired", LinkType.WIRED, "wired"),
        Probe("laptop-living", LinkType.WIFI, "ap-living-room"),
        Probe("laptop-office", LinkType.WIFI, "ap-office"),
    ]


# ---------------------------------------------------------------------------
# The two verdicts that matter most
# ---------------------------------------------------------------------------


def test_backbone_outage_is_diagnosed_as_all_probes(harness: Harness) -> None:
    """GROUND TRUTH: the internet drops for everyone at once.

    Every probe -- wired and WiFi -- loses all external anchors simultaneously, while the
    gateway keeps answering. This is a modem/ISP/router-WAN failure. The system MUST call
    it backbone and exonerate WiFi; calling it anything narrower would send the user
    chasing the wrong component.
    """
    probes = _probes()
    n = 20
    for p in probes:
        harness.register(p)
        harness.feed(
            p,
            {
                "gateway": _ok(n),  # LAN side fine everywhere
                "anchor-primary": _outage(n, 5, 12),  # internet gone for all
                "anchor-secondary": _outage(n, 5, 12),
            },
        )

    incidents = harness.diagnose(NOW - 10_000, NOW + n * TICK_MS)

    assert len(incidents) == 1, f"expected one correlated incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc["scope"] == "all_probes", f"backbone outage misdiagnosed as {inc['scope']!r}"
    assert inc["probe_count"] == 4


def test_single_ap_failure_is_not_diagnosed_as_backbone(harness: Harness) -> None:
    """GROUND TRUTH: one access point dies; the rest of the house is fine.

    Two probes sit behind the office AP; both lose everything -- including the gateway,
    because their whole link is gone -- while the wired probes and the living-room AP stay
    up. The system MUST localize this to that AP and MUST NOT call it backbone. This is the
    hardest and most valuable distinction: from inside the affected room it looks exactly
    like a total outage, and only the *other* probes staying up reveals the truth.
    """
    probes = [
        Probe("pi-wired", LinkType.WIRED, "wired"),
        Probe("desktop-wired", LinkType.WIRED, "wired"),
        Probe("office-a", LinkType.WIFI, "ap-office"),
        Probe("office-b", LinkType.WIFI, "ap-office"),  # second probe, same AP
        Probe("living", LinkType.WIFI, "ap-living-room"),
    ]
    n = 20
    for p in probes:
        harness.register(p)

    # Healthy probes: everything up throughout.
    for name in ("pi-wired", "desktop-wired", "living"):
        p = next(x for x in probes if x.name == name)
        harness.feed(p, {"gateway": _ok(n), "anchor-primary": _ok(n), "anchor-secondary": _ok(n)})

    # The two office probes lose EVERYTHING -- their AP is gone, so even the gateway is
    # unreachable from them.
    for name in ("office-a", "office-b"):
        p = next(x for x in probes if x.name == name)
        harness.feed(
            p,
            {
                "gateway": _outage(n, 5, 12),
                "anchor-primary": _outage(n, 5, 12),
                "anchor-secondary": _outage(n, 5, 12),
            },
        )

    incidents = harness.diagnose(NOW - 10_000, NOW + n * TICK_MS)

    assert len(incidents) == 1, f"expected one incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc["scope"] != "all_probes", (
        "a single-AP failure was misdiagnosed as a backbone outage -- "
        "the system would send the user to chase the modem instead of the AP"
    )
    assert inc["scope"] == "single_ap", f"expected single_ap, got {inc['scope']!r}"
    assert inc["probe_count"] == 2


def test_gateway_up_internet_down_across_all_probes(harness: Harness) -> None:
    """GROUND TRUTH: the exact reported symptom, house-wide.

    Every probe can reach its gateway but not the internet -- "full bars, nothing loads"
    everywhere at once. Detection must fire gateway_up_internet_down per probe, and
    correlation must roll them into one backbone incident.
    """
    probes = _probes()
    n = 20
    for p in probes:
        harness.register(p)
        harness.feed(
            p,
            {
                "gateway": _ok(n),
                "anchor-primary": _outage(n, 4, 14),
                "anchor-secondary": _outage(n, 4, 14),
            },
        )

    incidents = harness.diagnose(NOW - 10_000, NOW + n * TICK_MS)

    assert len(incidents) == 1
    assert incidents[0]["scope"] == "all_probes"


def test_healthy_network_produces_no_incident(harness: Harness) -> None:
    """The negative control: a clean network must yield no diagnosis at all.

    A system that invents incidents from healthy data is worse than useless -- it trains
    the user to ignore it.
    """
    probes = _probes()
    n = 20
    for p in probes:
        harness.register(p)
        harness.feed(p, {"gateway": _ok(n), "anchor-primary": _ok(n), "anchor-secondary": _ok(n)})

    incidents = harness.diagnose(NOW - 10_000, NOW + n * TICK_MS)
    assert incidents == [], "invented an incident from a healthy network"
