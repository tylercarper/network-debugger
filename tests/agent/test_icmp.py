"""ICMP collector and runner tests.

The collector's contract is narrow but strict: it must always return a Sample and never
raise. A failed ping is a *measurement*, not an error -- failures are the entire point of
this system, and an exception escaping the collector would drop exactly the data an
outage produces.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from icmplib import ICMPLibError, NameLookupError, SocketPermissionError

from netdbg_agent.collectors.icmp import IcmpTarget, ping_target
from netdbg_agent.config import AgentConfig
from netdbg_agent.runner import AgentRunner, default_targets
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_common.enums import EventType, SampleKind
from netdbg_common.timeutil import ClockStep

NOW = 1_700_000_000_000
TARGET = IcmpTarget(address="192.0.2.1", label="test-target")


class FakeHost:
    def __init__(self, alive: bool, rtts: list[float]) -> None:
        self.is_alive = alive
        self.rtts = rtts


# ---------------------------------------------------------------------------
# The collector never raises
# ---------------------------------------------------------------------------


def test_successful_ping_records_rtt() -> None:
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [12.34])):
        sample = ping_target(TARGET, ts=NOW)

    assert sample.success
    assert sample.value_ms == 12.34
    assert sample.ts == NOW
    assert sample.kind == SampleKind.ICMP
    assert sample.target == "test-target"


def test_timeout_is_a_measurement_not_an_error() -> None:
    """No reply is ordinary packet loss -- the signal this system exists to capture."""
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
        sample = ping_target(TARGET, ts=NOW)

    assert not sample.success
    assert sample.value_ms is None
    assert sample.ts == NOW, "a failed measurement still needs its timestamp"


@pytest.mark.parametrize(
    "error",
    [
        NameLookupError("dns broke"),
        SocketPermissionError("need root"),
        ICMPLibError("generic"),
        OSError(101, "Network is unreachable"),
    ],
)
def test_errors_become_failed_samples(error: Exception) -> None:
    """Every failure mode yields a Sample.

    If any of these escaped, one bad target would take down collection for all of them.
    """
    with patch("netdbg_agent.collectors.icmp.ping", side_effect=error):
        sample = ping_target(TARGET, ts=NOW)

    assert not sample.success
    assert sample.ts == NOW


def test_error_codes_distinguish_local_from_network_failure() -> None:
    """ "Cannot send" and "nothing replied" are different diagnoses.

    The first is a problem with the probe; the second is a finding about the network.
    Collapsing them would make a misconfigured probe look like an outage.
    """
    with patch("netdbg_agent.collectors.icmp.ping", side_effect=SocketPermissionError("x")):
        permission = ping_target(TARGET, ts=NOW)
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
        timeout = ping_target(TARGET, ts=NOW)

    assert permission.code is not None, "local failure should carry a reason code"
    assert timeout.code is None, "ordinary loss is not an error condition"


def test_alive_but_no_rtt_treated_as_failure() -> None:
    """Defensive: a host reported alive with no RTT has nothing to record."""
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [])):
        assert not ping_target(TARGET, ts=NOW).success


def test_metadata_is_carried_through() -> None:
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [5.0])):
        sample = ping_target(TARGET, ts=NOW, seq=42, interval_slip_ms=250)

    assert sample.seq == 42
    assert sample.interval_slip_ms == 250


def test_label_is_recorded_not_address() -> None:
    """Samples are keyed by role, not address.

    A gateway's IP can change -- router reboot, replacement -- but its role in the
    diagnosis does not. Recording 'gateway' keeps a probe's history continuous across
    that change, which matters because the IP change is itself an event to correlate.
    """
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        sample = ping_target(IcmpTarget(address="10.9.9.9", label="gateway"), ts=NOW)

    assert sample.target == "gateway"
    assert "10.9.9.9" not in sample.target


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------


def test_two_anchors_are_always_present() -> None:
    """One anchor cannot distinguish "internet down" from "Cloudflare blipped".

    That distinction is the whole question during an outage, so a second independent
    anchor is not optional.
    """
    targets = default_targets(gateway="192.168.1.1")
    addresses = {t.address for t in targets}

    assert "1.1.1.1" in addresses
    assert "8.8.8.8" in addresses
    assert len({t.label for t in targets}) == len(targets), "labels must be unique"


def test_gateway_included_when_known() -> None:
    targets = default_targets(gateway="192.168.1.1")
    assert targets[0].label == "gateway"
    assert targets[0].address == "192.168.1.1"


def test_no_gateway_still_measures_anchors() -> None:
    """A probe with no default route must keep measuring.

    The absence of a gateway is itself diagnostic, and anchor results still distinguish
    "no route at all" from "route exists but the internet is unreachable".
    """
    targets = default_targets(gateway=None)

    assert len(targets) == 2
    assert all(t.label != "gateway" for t in targets)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


@pytest.fixture
def runner(tmp_path: Any) -> AgentRunner:
    spool = Spool(tmp_path / "spool.db")
    cfg = AgentConfig(server_url="http://127.0.0.1:1", name="test")
    shipper = Shipper(cfg, spool)
    return AgentRunner(
        config=cfg,
        spool=spool,
        shipper=shipper,
        targets=[IcmpTarget(address="192.0.2.1", label="gateway")],
    )


def test_collect_writes_to_spool_before_shipping(runner: AgentRunner) -> None:
    """Write-before-ship: measurements are durable before the network is touched."""
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [3.0])):
        samples = runner.collect_once()

    assert len(samples) == 1
    assert runner.spool.pending_count() == 1, "sample must be spooled, not held in memory"


def test_collection_survives_unreachable_server(runner: AgentRunner) -> None:
    """The defining case: measurement continues while the server is unreachable.

    The runner's shipper points at a dead port here, exactly as during an outage.
    """
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
        for _ in range(10):
            runner.collect_once()
            runner.ship_if_due()

    assert runner.spool.pending_count() == 10, "measurements lost while server was down"


def test_sequence_numbers_increment(runner: AgentRunner) -> None:
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        first = runner.collect_once()
        second = runner.collect_once()

    assert first[0].seq == 0
    assert second[0].seq == 1


def test_clock_step_is_spooled_as_an_event(runner: AgentRunner, tmp_path: Any) -> None:
    """A wall-clock jump must be recorded, not silently absorbed.

    Without this, a laptop's overnight sleep looks like a flawless outage spanning the
    entire night.
    """
    # Monotonic barely advanced while wall clock jumped an hour -- the signature of a
    # suspend rather than an NTP correction.
    runner._pending_clock_steps.append(
        ClockStep(detected_at_ms=NOW, delta_ms=3_600_000, monotonic_gap_ms=10, expected_gap_ms=1000)
    )

    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
        runner.collect_once()

    batch = runner.spool.claim_batch("b1", limit=100)
    assert len(batch.events) == 1
    assert batch.events[0].event_type == EventType.CLOCK_STEP
    assert batch.events[0].subtype == "suspend", "monotonic stalled -- this was a sleep"


def test_one_bad_target_does_not_stop_the_others(tmp_path: Any) -> None:
    """A single failing target must not cost the measurements from the rest."""
    spool = Spool(tmp_path / "s.db")
    cfg = AgentConfig(server_url="http://127.0.0.1:1")
    runner = AgentRunner(
        config=cfg,
        spool=spool,
        shipper=Shipper(cfg, spool),
        targets=[
            IcmpTarget(address="192.0.2.1", label="gateway"),
            IcmpTarget(address="1.1.1.1", label="anchor-primary"),
        ],
    )

    def flaky(address: str, **kw: object) -> FakeHost:
        if address == "192.0.2.1":
            raise SocketPermissionError("boom")
        return FakeHost(True, [8.0])

    with patch("netdbg_agent.collectors.icmp.ping", side_effect=flaky):
        samples = runner.collect_once()

    assert len(samples) == 2
    assert not samples[0].success
    assert samples[1].success, "healthy target lost because a sibling failed"
