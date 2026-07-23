"""Scheduler and multi-cadence collection tests.

Two things need proving: that each collector fires at its own rate (not every tick), and
that a slow collector's failure never costs the rest of the tick -- especially the ICMP
samples, which are the fast loop that catches brief blips.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from netdbg_agent.collectors.icmp import IcmpTarget
from netdbg_agent.config import AgentConfig
from netdbg_agent.runner import AgentRunner
from netdbg_agent.schedule import ScheduledCollector
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_common.enums import SampleKind
from netdbg_common.models import Sample

NOW = 1_700_000_000_000


class FakeHost:
    def __init__(self, alive: bool, rtts: list[float]) -> None:
        self.is_alive = alive
        self.rtts = rtts


# ---------------------------------------------------------------------------
# ScheduledCollector
# ---------------------------------------------------------------------------


def test_first_call_is_always_due() -> None:
    """Every collector must fire once promptly on startup.

    Otherwise a 15s collector would produce nothing for its first 15 seconds, blinding
    the probe during exactly the window an operator is most likely watching.
    """
    sc = ScheduledCollector(name="x", interval_s=10.0, collect=lambda ts: [])
    assert sc.is_due(100.0)


def test_not_due_until_interval_elapses() -> None:
    sc = ScheduledCollector(name="x", interval_s=10.0, collect=lambda ts: [], jitter_frac=0.0)
    sc.is_due(100.0)  # consumes the first firing

    assert not sc.is_due(105.0), "should not fire again before the interval"
    assert sc.is_due(111.0), "should fire once the interval has passed"


def test_jitter_spreads_firing() -> None:
    """Jitter must actually vary the next-due time.

    Without it, N probes that start together fire their DNS/HTTP checks in lockstep and
    contend on the network they are trying to measure.
    """
    import random

    # Sample the next-due offsets directly: with nonzero jitter, repeated is_due calls
    # from the same base time must not all land on the same next-due value.
    offsets = set()
    for seed in range(10):
        sc = ScheduledCollector(
            name="x",
            interval_s=10.0,
            collect=lambda ts: [],
            jitter_frac=0.5,
            _rng=random.Random(seed),
        )
        sc.is_due(0.0)
        offsets.add(round(sc._next_due_mono, 4))

    assert len(offsets) > 1, "next-due times are identical across seeds; jitter is not applied"


# ---------------------------------------------------------------------------
# Multi-cadence collection in the runner
# ---------------------------------------------------------------------------


@pytest.fixture
def runner(tmp_path: Path) -> AgentRunner:
    """A runner wired with a real collector set but stubbed collect callbacks.

    Uses build_extra_collectors so the scheduler exists, then replaces the callbacks so
    nothing touches the live network.
    """
    spool = Spool(tmp_path / "spool.db")
    cfg = AgentConfig(
        server_url="http://127.0.0.1:1",
        iface_interval_s=5.0,
        dns_interval_s=10.0,
        http_interval_s=15.0,
    )
    r = AgentRunner(
        config=cfg,
        spool=spool,
        shipper=Shipper(cfg, spool),
        targets=[IcmpTarget(address="192.0.2.1", label="gateway")],
    )

    # Inject scheduled collectors with cheap fakes, since the fixture supplied explicit
    # targets (which suppresses auto-build).
    def dns(ts: int) -> list[Sample]:
        return [Sample(ts=ts, kind=SampleKind.DNS, target="dns", success=True)]

    def http(ts: int) -> list[Sample]:
        return [Sample(ts=ts, kind=SampleKind.HTTP, target="http", success=True)]

    def iface(ts: int) -> list[Sample]:
        return [Sample(ts=ts, kind=SampleKind.IFACE, target="eth0", success=True)]

    r._scheduled = [
        ScheduledCollector(name="iface", interval_s=5.0, collect=iface, jitter_frac=0.0),
        ScheduledCollector(name="dns", interval_s=10.0, collect=dns, jitter_frac=0.0),
        ScheduledCollector(name="http", interval_s=15.0, collect=http, jitter_frac=0.0),
    ]
    return r


def test_icmp_runs_every_tick(runner: AgentRunner) -> None:
    """ICMP is the fast loop -- it must appear in every single tick."""
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        for _ in range(3):
            samples = runner.collect_once()
            icmp = [s for s in samples if s.kind == SampleKind.ICMP]
            assert icmp, "every tick must contain an ICMP sample"


def test_slower_collectors_do_not_run_every_tick(runner: AgentRunner) -> None:
    """DNS/HTTP/iface must fire on their own cadence, not every tick.

    Running them every second would rate-limit the probed services and bury the DB in
    redundant rows.
    """
    kinds_per_tick: list[set[SampleKind]] = []
    # Ticks are ~instantaneous in the test, so monotonic barely advances; only the first
    # tick should fire the scheduled collectors (their "first call is due" rule).
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        for _ in range(3):
            samples = runner.collect_once()
            kinds_per_tick.append({s.kind for s in samples})

    assert SampleKind.DNS in kinds_per_tick[0], "scheduled collectors fire on first tick"
    # Subsequent near-instant ticks should be ICMP-only, since no interval has elapsed.
    assert kinds_per_tick[1] == {SampleKind.ICMP}
    assert kinds_per_tick[2] == {SampleKind.ICMP}


def test_all_samples_land_in_one_durable_write(runner: AgentRunner) -> None:
    """A tick's samples are spooled together, so a crash never leaves a partial tick."""
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        runner.collect_once()

    # First tick fires every collector: 1 ICMP + iface + dns + http = 4 samples, all
    # written in the single durable spool write at the end of the tick.
    assert runner.spool.pending_count() == 4, "all four collectors' samples should be spooled"


def test_a_failing_collector_does_not_lose_the_tick(runner: AgentRunner) -> None:
    """If one scheduled collector raises, ICMP and the others still get recorded.

    This is the whole reason each scheduled collect() is wrapped: a bug in the DNS
    collector must not blind the probe to everything else.
    """

    def exploding(ts: int) -> list[Sample]:
        raise RuntimeError("dns collector blew up")

    runner._scheduled[1] = ScheduledCollector(
        name="dns", interval_s=10.0, collect=exploding, jitter_frac=0.0
    )

    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        samples = runner.collect_once()

    kinds = {s.kind for s in samples}
    assert SampleKind.ICMP in kinds, "ICMP lost because a sibling collector failed"
    assert SampleKind.IFACE in kinds, "iface lost because DNS failed"
    assert SampleKind.DNS not in kinds, "the failing collector should contribute nothing"


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


def test_capabilities_reflect_active_collectors(runner: AgentRunner) -> None:
    """A probe advertises what it can measure, so the dashboard shows real gaps as known.

    'No DNS on this probe' should read as a capability limit, not as missing data.
    """
    caps = runner.probe_info().capabilities
    assert "icmp.privileged" in caps
    assert "dns" in caps
    assert "http" in caps
    assert "iface" in caps
