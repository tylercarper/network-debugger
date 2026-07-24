"""Detection rule tests, over synthetic sample windows.

Rules are pure functions of a ProbeWindow, so these need no database -- a window is built
in memory, fed to the rule, and its events asserted. The bulk of the attention goes to
gateway_up_internet_down, because it is the headline symptom and the detection most prone
to false positives: for each way it could cry wolf there is a test asserting it stays
quiet or downgrades.
"""

from __future__ import annotations

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.rules.dns import DnsFailureRule
from netdbg_server.detect.rules.gateway_up_internet_down import GatewayUpInternetDownRule
from netdbg_server.detect.rules.latency import LatencySpikeRule
from netdbg_server.detect.rules.link import LinkChangeRule
from netdbg_server.detect.rules.loss import LossBurstRule
from netdbg_server.detect.rules.outage import OutageRule
from netdbg_server.detect.window import ProbeWindow, SampleRow

NOW = 1_700_000_000_000


class WindowBuilder:
    """Fluent builder for a ProbeWindow, one target-series at a time."""

    def __init__(self, interval_ms: int = 1000) -> None:
        self._interval = interval_ms
        self._window = ProbeWindow(probe_id="p", from_ts=NOW, to_ts=NOW + 10_000_000)

    def icmp(self, target: str, pattern: str, *, rtt: float = 10.0) -> WindowBuilder:
        """pattern: 'o'=ok, 'x'=fail, one sample per interval."""
        self._add(SampleKind.ICMP, target, pattern, ok_rtt=rtt)
        return self

    def dns(self, target: str, pattern: str) -> WindowBuilder:
        self._add(SampleKind.DNS, target, pattern, ok_rtt=20.0)
        return self

    def http(self, target: str, pattern: str, *, code_ok: int = 204) -> WindowBuilder:
        self._add(SampleKind.HTTP, target, pattern, ok_rtt=30.0, ok_code=code_ok)
        return self

    def iface(self, name: str, pattern: str, *, absent: bool = False) -> WindowBuilder:
        self._add(SampleKind.IFACE, name, pattern, ok_rtt=0.0, fail_code=-1 if absent else None)
        return self

    def icmp_rtts(self, target: str, rtts: list[float]) -> WindowBuilder:
        for i, v in enumerate(rtts):
            self._window.add(
                SampleRow(ts=NOW + i * self._interval, success=True, value_ms=v, code=None),
                SampleKind.ICMP,
                target,
            )
        return self

    def _add(
        self,
        kind: SampleKind,
        target: str,
        pattern: str,
        *,
        ok_rtt: float,
        ok_code: int | None = None,
        fail_code: int | None = None,
    ) -> None:
        for i, c in enumerate(pattern):
            ok = c == "o"
            self._window.add(
                SampleRow(
                    ts=NOW + i * self._interval,
                    success=ok,
                    value_ms=ok_rtt if ok else None,
                    code=ok_code if ok else fail_code,
                ),
                kind,
                target,
            )

    def build(self) -> ProbeWindow:
        return self._window


# ---------------------------------------------------------------------------
# Outage
# ---------------------------------------------------------------------------


def test_outage_fires_when_all_targets_fail() -> None:
    window = (
        WindowBuilder()
        .icmp("gateway", "ooxxxxxoo")
        .icmp("anchor-primary", "ooxxxxxoo")
        .icmp("anchor-secondary", "ooxxxxxoo")
        .build()
    )
    events = OutageRule().detect(window)

    assert len(events) == 1
    assert events[0].event_type == EventType.OUTAGE
    assert events[0].severity == Severity.CRITICAL


def test_outage_does_not_fire_if_any_target_survives() -> None:
    """One surviving target means this is not a *total* outage.

    It might be a loss burst or gateway-up-internet-down -- a different, more specific
    event -- so calling it an outage would mislabel the cause.
    """
    window = (
        WindowBuilder()
        .icmp("gateway", "ooooooooo")  # gateway stays up
        .icmp("anchor-primary", "ooxxxxxoo")
        .icmp("anchor-secondary", "ooxxxxxoo")
        .build()
    )
    assert OutageRule().detect(window) == []


def test_outage_ignores_single_sample_blip() -> None:
    window = (
        WindowBuilder()
        .icmp("gateway", "ooxoo")
        .icmp("anchor-primary", "ooxoo")
        .icmp("anchor-secondary", "ooxoo")
        .build()
    )
    assert OutageRule().detect(window) == []


# ---------------------------------------------------------------------------
# gateway_up_internet_down -- the headline symptom and its false-positive guards
# ---------------------------------------------------------------------------


def test_gwid_fires_when_gateway_up_and_anchors_down() -> None:
    window = (
        WindowBuilder()
        .icmp("gateway", "oooooooo")
        .icmp("anchor-primary", "ooxxxxoo")
        .icmp("anchor-secondary", "ooxxxxoo")
        .build()
    )
    events = GatewayUpInternetDownRule().detect(window)

    assert len(events) == 1
    assert events[0].event_type == EventType.GATEWAY_UP_INTERNET_DOWN
    assert events[0].severity == Severity.CRITICAL


def test_gwid_downgrades_to_icmp_filtered_when_http_succeeds() -> None:
    """The most important guard (#14): if HTTP works, ICMP is merely filtered.

    Routers rate-limit ICMP, so anchor pings can fail while real traffic flows. An HTTP
    204 during the window proves the internet is up -- so this must NOT be a critical
    outage, but a low-severity icmp_filtered note.
    """
    window = (
        WindowBuilder()
        .icmp("gateway", "oooooooo")
        .icmp("anchor-primary", "ooxxxxoo")
        .icmp("anchor-secondary", "ooxxxxoo")
        .http("http-204", "oooooooo")  # HTTP works throughout
        .build()
    )
    events = GatewayUpInternetDownRule().detect(window)

    assert len(events) == 1
    assert events[0].event_type == EventType.ICMP_FILTERED
    assert events[0].severity == Severity.INFO


def test_gwid_still_fires_when_http_also_fails() -> None:
    """If HTTP fails too, the internet really is down -- assert it, do not downgrade."""
    window = (
        WindowBuilder()
        .icmp("gateway", "ooooooooo")
        .icmp("anchor-primary", "ooxxxxooo")
        .icmp("anchor-secondary", "ooxxxxooo")
        .http("http-204", "ooxxxxooo")
        .build()
    )
    events = GatewayUpInternetDownRule().detect(window)

    assert len(events) == 1
    assert events[0].event_type == EventType.GATEWAY_UP_INTERNET_DOWN


def test_gwid_does_not_fire_when_only_one_anchor_fails() -> None:
    """One anchor failing could just be that provider blipping.

    Requiring both anchors down is what makes the signal trustworthy.
    """
    window = (
        WindowBuilder()
        .icmp("gateway", "oooooooo")
        .icmp("anchor-primary", "ooxxxxoo")
        .icmp("anchor-secondary", "oooooooo")  # 8.8.8.8 fine
        .build()
    )
    assert GatewayUpInternetDownRule().detect(window) == []


def test_gwid_does_not_fire_during_full_outage() -> None:
    """If the gateway is also down, this is a plain outage, not gateway-up-internet-down.

    The gateway being up is the defining condition; without it the rule must stay silent
    and leave the event to OutageRule.
    """
    window = (
        WindowBuilder()
        .icmp("gateway", "ooxxxxoo")  # gateway down too
        .icmp("anchor-primary", "ooxxxxoo")
        .icmp("anchor-secondary", "ooxxxxoo")
        .build()
    )
    assert GatewayUpInternetDownRule().detect(window) == []


def test_gwid_subtypes_on_dns_failure() -> None:
    """When DNS also fails, the event is sub-classified for a sharper diagnosis."""
    window = (
        WindowBuilder()
        .icmp("gateway", "ooooooooo")
        .icmp("anchor-primary", "ooxxxxooo")
        .icmp("anchor-secondary", "ooxxxxooo")
        .dns("dns-cloudflare", "oxxxxxooo")
        .build()
    )
    events = GatewayUpInternetDownRule().detect(window)
    assert events[0].subtype == "dns_and_reachability"
    assert events[0].confidence > 0.8


def test_gwid_needs_no_anchors_gracefully() -> None:
    """A probe with no anchor series simply produces no such event, not a crash."""
    window = WindowBuilder().icmp("gateway", "oooooooo").build()
    assert GatewayUpInternetDownRule().detect(window) == []


# ---------------------------------------------------------------------------
# Loss burst
# ---------------------------------------------------------------------------


def test_loss_burst_fires_on_partial_loss() -> None:
    # 30-sample window, ~30% loss -- elevated but not a full outage.
    pattern = ("ooxooxooxo" * 3)[:30]  # 9 fails in 30 = 30%
    window = WindowBuilder().icmp("anchor-primary", pattern).build()
    events = LossBurstRule().detect(window)

    assert any(e.event_type == EventType.LOSS_BURST for e in events)


def test_loss_burst_ignores_clean_window() -> None:
    window = WindowBuilder().icmp("anchor-primary", "o" * 40).build()
    assert LossBurstRule().detect(window) == []


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------


def test_latency_spike_fires_relative_to_baseline() -> None:
    """A stretch of high RTT against a low baseline is a spike."""
    rtts = [10.0] * 15 + [200.0] * 8 + [10.0] * 5  # baseline ~10ms, spike to 200ms
    window = WindowBuilder().icmp_rtts("anchor-primary", rtts).build()
    events = LatencySpikeRule().detect(window)

    assert any(e.event_type == EventType.LATENCY_SPIKE for e in events)


def test_latency_stable_high_baseline_does_not_spike() -> None:
    """A consistently slow probe is not spiking -- its baseline is just higher.

    An absolute threshold would cry wolf here; the per-probe baseline must not.
    """
    rtts = [80.0] * 30  # slow but stable
    window = WindowBuilder().icmp_rtts("anchor-primary", rtts).build()
    assert LatencySpikeRule().detect(window) == []


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def test_dns_gateway_only_failure_blames_forwarder() -> None:
    """Gateway resolver failing while public ones answer = router's DNS forwarder."""
    window = WindowBuilder().dns("dns-gateway", "oxxxxoo").dns("dns-cloudflare", "ooooooo").build()
    events = DnsFailureRule().detect(window)

    gw_events = [e for e in events if e.evidence.get("resolver") == "dns-gateway"]
    assert gw_events
    assert gw_events[0].subtype == "router_forwarder"


def test_dns_all_resolvers_failing_is_critical() -> None:
    window = WindowBuilder().dns("dns-gateway", "oxxxxoo").dns("dns-cloudflare", "oxxxxoo").build()
    events = DnsFailureRule().detect(window)
    assert any(e.subtype == "all_resolvers" and e.severity == Severity.CRITICAL for e in events)


# ---------------------------------------------------------------------------
# Link change
# ---------------------------------------------------------------------------


def test_link_down_is_detected() -> None:
    window = WindowBuilder().iface("eth0", "ooxxxoo").build()
    events = LinkChangeRule().detect(window)

    assert len(events) == 1
    assert events[0].event_type == EventType.LINK_CHANGE
    assert events[0].subtype == "down"


def test_absent_interface_is_distinct_from_down() -> None:
    window = WindowBuilder().iface("wlan0", "ooxxxoo", absent=True).build()
    events = LinkChangeRule().detect(window)
    assert events[0].subtype == "absent"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_every_event_carries_evidence() -> None:
    """An event with no evidence is a claim with no receipt."""
    window = (
        WindowBuilder()
        .icmp("gateway", "ooxxxxxoo")
        .icmp("anchor-primary", "ooxxxxxoo")
        .icmp("anchor-secondary", "ooxxxxxoo")
        .build()
    )
    for event in OutageRule().detect(window):
        assert event.evidence, "event must carry the values that triggered it"
        assert "detector" in event.evidence
