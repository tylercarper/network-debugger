"""Agent runner: the loop that measures, spools, and ships.

Ordering inside the loop is deliberate. Measurements are taken and written to the spool
*before* any shipping is attempted, so a failure to reach the server can never cost a
measurement. Shipping is best-effort; collection is not.
"""

from __future__ import annotations

import logging
import platform
import random
import time
from dataclasses import dataclass, field

from netdbg_agent.collectors.dns_probe import DnsProbe, DnsTarget
from netdbg_agent.collectors.gateway import discover_gateway
from netdbg_agent.collectors.http_probe import DEFAULT_CHECK_URL, HttpProbe, HttpTarget
from netdbg_agent.collectors.icmp import IcmpTarget, ping_target
from netdbg_agent.collectors.iface import sample_interface
from netdbg_agent.config import AgentConfig
from netdbg_agent.schedule import ScheduledCollector
from netdbg_agent.ship_worker import ShipWorker
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_common.enums import EventType, LinkType, Severity
from netdbg_common.models import Event, ProbeInfo, Sample
from netdbg_common.timeutil import ClockStep, MonotonicClock

__all__ = ["AgentRunner", "default_targets"]

log = logging.getLogger("netdbg.agent")

# Two external anchors, not one. If a single anchor fails we cannot distinguish "the
# internet is down" from "Cloudflare is having a moment" -- and that difference is the
# whole question when diagnosing an outage.
ANCHOR_PRIMARY = "1.1.1.1"
ANCHOR_SECONDARY = "8.8.8.8"


def _default_iface_names() -> list[str]:
    """Best-effort pick of the interface to watch when the gateway's is unknown.

    Returns the first non-loopback interface that is up. Empty when none can be found,
    in which case the interface collector simply contributes nothing rather than erroring.
    """
    try:
        import psutil

        for name, stats in psutil.net_if_stats().items():
            if stats.isup and name != "lo":
                return [name]
    except Exception:  # pragma: no cover - psutil edge cases on exotic hosts
        pass
    return []


def default_targets(gateway: str | None) -> list[IcmpTarget]:
    """Build the standard target set.

    The gateway is included when known: it is what separates "my link to the router is
    broken" from "the router's link to the world is broken", which is the first fork in
    any diagnosis.
    """
    targets = [
        IcmpTarget(address=ANCHOR_PRIMARY, label="anchor-primary"),
        IcmpTarget(address=ANCHOR_SECONDARY, label="anchor-secondary"),
    ]
    if gateway is not None:
        targets.insert(0, IcmpTarget(address=gateway, label="gateway"))
    return targets


@dataclass
class AgentRunner:
    """Owns the measure -> spool -> ship cycle."""

    config: AgentConfig
    spool: Spool
    shipper: Shipper
    clock: MonotonicClock = field(default_factory=MonotonicClock)

    targets: list[IcmpTarget] = field(default_factory=list)
    _seq: int = 0
    _last_cycle_mono: float | None = None
    _next_ship_at: float = 0.0
    _pending_clock_steps: list[ClockStep] = field(default_factory=list)
    _scheduled: list[ScheduledCollector] = field(default_factory=list)
    _dns_probes: list[DnsProbe] = field(default_factory=list)
    _http_probes: list[HttpProbe] = field(default_factory=list)
    _iface_names: list[str] = field(default_factory=list)

    # When targets are supplied explicitly, the slower collectors are not auto-built.
    # This keeps tests that exercise the ICMP/spool/ship path from accidentally issuing
    # real DNS and HTTP requests to the live network. Production leaves targets empty, so
    # discovery and the full collector set run.
    build_extra_collectors: bool = True

    def __post_init__(self) -> None:
        gw: object = None
        explicit_targets = bool(self.targets)
        if not self.targets:
            gw = discover_gateway()
            if gw is None:
                # Not fatal. A probe with no default route still measures the anchors,
                # and the absence of a gateway is itself worth recording.
                log.warning("no default gateway found; continuing without gateway target")
            else:
                log.info("discovered gateway %s on %s", gw.address, gw.interface)
            self.targets = default_targets(gw.address if gw else None)

        # Route clock discontinuities into the spool as events. This is what stops a
        # laptop's overnight sleep from being recorded as a flawless outage.
        self.clock = MonotonicClock(on_step=self._pending_clock_steps.append)

        if self.build_extra_collectors and not self._scheduled and not explicit_targets:
            self._build_collectors(gw)

    def _build_collectors(self, gateway: object) -> None:
        """Assemble the per-cadence collector set.

        ICMP is intentionally *not* here: it runs every tick as the fast loop, so it is
        collected directly rather than through the scheduler. Everything slower goes
        through :class:`ScheduledCollector` at its own interval.
        """
        gw_addr = getattr(gateway, "address", None)

        # DNS against the gateway resolver and both public anchors. The gateway resolver
        # is included only when known: comparing it against the public ones is what
        # localizes a DNS fault to the router's forwarder.
        dns_targets = [
            DnsTarget(address=ANCHOR_PRIMARY, label="dns-cloudflare"),
            DnsTarget(address=ANCHOR_SECONDARY, label="dns-google"),
        ]
        if isinstance(gw_addr, str):
            dns_targets.insert(0, DnsTarget(address=gw_addr, label="dns-gateway"))
        self._dns_probes = [DnsProbe(t) for t in dns_targets]

        self._http_probes = [HttpProbe(HttpTarget(url=DEFAULT_CHECK_URL, label="http-204"))]

        # The interface carrying the default route is the one worth watching. Falls back
        # to whatever non-loopback interface is up if the gateway's is unknown.
        iface = getattr(gateway, "interface", None)
        self._iface_names = [iface] if isinstance(iface, str) else _default_iface_names()

        self._scheduled = [
            ScheduledCollector(
                name="iface",
                interval_s=self.config.iface_interval_s,
                collect=self._collect_iface,
            ),
            ScheduledCollector(
                name="dns",
                interval_s=self.config.dns_interval_s,
                collect=self._collect_dns,
            ),
            ScheduledCollector(
                name="http",
                interval_s=self.config.http_interval_s,
                collect=self._collect_http,
            ),
        ]

    # -- identity ----------------------------------------------------------

    def probe_info(self) -> ProbeInfo:
        # Capabilities advertise what this probe can actually measure, so the server and
        # dashboard can show "no DNS here" as a known limitation rather than missing data.
        caps = ["icmp.privileged"]
        # Advertise every scheduled collector by name, so the set reflects what is
        # actually running regardless of how it was wired.
        caps.extend(sc.name for sc in self._scheduled)
        return ProbeInfo(
            name=self.config.resolved_name(),
            link_type=LinkType.UNKNOWN,
            os_name=platform.system(),
            os_version=platform.release(),
            agent_version="0.1.0",
            capabilities=caps,
        )

    def ensure_registered(self) -> bool:
        if self.shipper.is_registered:
            return True
        return self.shipper.register(self.probe_info())

    # -- per-collector callbacks -------------------------------------------

    def _collect_dns(self, ts: int) -> list[Sample]:
        return [p.resolve(ts, seq=self._seq) for p in self._dns_probes]

    def _collect_http(self, ts: int) -> list[Sample]:
        return [p.check(ts, seq=self._seq) for p in self._http_probes]

    def _collect_iface(self, ts: int) -> list[Sample]:
        return [sample_interface(name, ts, seq=self._seq) for name in self._iface_names]

    # -- one cycle ---------------------------------------------------------

    def collect_once(self) -> list[Sample]:
        """Run one tick: ICMP always, plus any scheduled collector that is due.

        Everything measured this tick is written to the spool in a single durable write,
        so a crash mid-tick loses either all of it or none of it -- never a partial tick
        that would read as a phantom gap.
        """
        now_mono = time.monotonic()
        slip_ms = self._compute_slip(now_mono)
        self._last_cycle_mono = now_mono

        # Detect wall-clock discontinuities before stamping anything.
        self.clock.check_step()
        ts = self.clock.now_ms()

        # ICMP is the fast loop: every tick, so it catches the brief blips slower
        # collectors would miss.
        samples: list[Sample] = [
            ping_target(t, ts=ts, seq=self._seq, interval_slip_ms=slip_ms) for t in self.targets
        ]

        for sc in self._scheduled:
            if sc.is_due(now_mono):
                try:
                    samples.extend(sc.run(ts))
                except Exception:
                    # A misbehaving collector must not lose the rest of the tick. ICMP
                    # and the other collectors have already run; drop only the offender.
                    log.exception("collector %s failed this tick; continuing", sc.name)

        self._seq += 1

        self.spool.add_samples(samples)
        self._flush_clock_steps()
        return samples

    def close(self) -> None:
        """Release collector resources (HTTP clients). Idempotent."""
        for p in self._http_probes:
            p.close()
        self._http_probes = []

    def _compute_slip(self, now_mono: float) -> int | None:
        """How far this cycle overran its schedule.

        A busy host delays the sampling loop, and a delayed sample can look like a
        failure to a naive detector. Recording the slip lets server-side detection
        exclude samples where the probe itself -- not the network -- was the problem.
        """
        if self._last_cycle_mono is None:
            return None
        actual_ms = (now_mono - self._last_cycle_mono) * 1000
        expected_ms = self.config.ship_interval_s * 1000
        slip = int(actual_ms - expected_ms)
        return slip if slip > 0 else None

    def _flush_clock_steps(self) -> None:
        if not self._pending_clock_steps:
            return
        events = [
            Event(
                event_type=EventType.CLOCK_STEP,
                severity=Severity.INFO,
                confidence=1.0,
                started_ts=step.detected_at_ms,
                subtype="suspend" if step.likely_suspend else "ntp_step",
                evidence={
                    "delta_ms": step.delta_ms,
                    "monotonic_gap_ms": step.monotonic_gap_ms,
                    "likely_suspend": step.likely_suspend,
                },
            )
            for step in self._pending_clock_steps
        ]
        self.spool.add_events(events)
        self._pending_clock_steps.clear()

    def ship_if_due(self, now_mono: float | None = None) -> None:
        """Ship inline. **For tests and single-shot use only.**

        The production loop uses :class:`ShipWorker` on a background thread instead. A
        blackholed server makes this call block for the full connect timeout, stalling
        collection during exactly the outage the probe exists to observe -- see #27.
        """
        now_mono = now_mono if now_mono is not None else time.monotonic()
        if now_mono < self._next_ship_at:
            return

        if not self.ensure_registered():
            self._next_ship_at = now_mono + self.shipper.next_delay_s()
            return

        result = self.shipper.ship_once(self.clock.now_ms())

        if result.fatal:
            # Credentials or protocol are wrong; re-registering is the only path that
            # can help, so force it on the next cycle.
            log.warning("fatal ship error, will re-register: %s", result.error)
            self.shipper.clear_identity()

        self._next_ship_at = now_mono + self.shipper.next_delay_s()

    # -- main loop ---------------------------------------------------------

    def run_forever(self, cycle_interval_s: float = 1.0) -> None:  # pragma: no cover
        """Measure on a jittered interval; a background thread handles delivery.

        Collection and shipping are deliberately decoupled. Shipping can block for
        seconds against a blackholed server, and **a measurement not taken cannot be
        recovered** -- unlike a delayed shipment, which the spool absorbs. So the
        collection loop must never wait on the network.

        Jitter keeps several probes on one network from synchronizing their bursts,
        which would make them contend and distort the very measurements they exist to
        take.
        """
        worker = ShipWorker(
            config=self.config,
            spool=self.spool,
            shipper=self.shipper,
            probe_info=self.probe_info(),
            clock=self.clock,
        )
        worker.start()
        last_trim = time.monotonic()

        try:
            while True:
                cycle_start = time.monotonic()
                try:
                    self.collect_once()

                    if cycle_start - last_trim > self.config.spool_trim_check_interval_s:
                        dropped = self.spool.trim()
                        if dropped:
                            log.warning("spool over capacity; dropped %d oldest rows", dropped)
                        last_trim = cycle_start
                except Exception:
                    # A collector bug must not kill the agent. Losing one cycle is far
                    # better than losing every cycle after it.
                    log.exception("cycle failed; continuing")

                elapsed = time.monotonic() - cycle_start
                jitter = random.uniform(0, cycle_interval_s * 0.1)
                time.sleep(max(0.0, cycle_interval_s - elapsed + jitter))
        finally:
            worker.stop()
            self.close()
