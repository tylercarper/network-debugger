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

from netdbg_agent.collectors.gateway import discover_gateway
from netdbg_agent.collectors.icmp import IcmpTarget, ping_target
from netdbg_agent.config import AgentConfig
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

    def __post_init__(self) -> None:
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

    # -- identity ----------------------------------------------------------

    def probe_info(self) -> ProbeInfo:
        return ProbeInfo(
            name=self.config.resolved_name(),
            link_type=LinkType.UNKNOWN,
            os_name=platform.system(),
            os_version=platform.release(),
            agent_version="0.1.0",
            capabilities=["icmp.privileged"],
        )

    def ensure_registered(self) -> bool:
        if self.shipper.is_registered:
            return True
        return self.shipper.register(self.probe_info())

    # -- one cycle ---------------------------------------------------------

    def collect_once(self) -> list[Sample]:
        """Measure every target once and write the results to the spool.

        Returns the samples for inspection; they are already durably stored by the time
        this returns.
        """
        now_mono = time.monotonic()
        slip_ms = self._compute_slip(now_mono)
        self._last_cycle_mono = now_mono

        # Detect wall-clock discontinuities before stamping anything.
        self.clock.check_step()

        samples = [
            ping_target(t, ts=self.clock.now_ms(), seq=self._seq, interval_slip_ms=slip_ms)
            for t in self.targets
        ]
        self._seq += 1

        self.spool.add_samples(samples)
        self._flush_clock_steps()
        return samples

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
        """Attempt delivery when the backoff schedule allows.

        Failure is expected and unremarkable here -- the network being unreachable is
        the condition this system exists to observe.
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
        """Measure on a jittered interval, shipping when due.

        Jitter keeps several probes on one network from synchronizing their bursts,
        which would make them contend with each other and distort the very measurements
        they exist to take.
        """
        self.ensure_registered()
        last_trim = time.monotonic()

        while True:
            cycle_start = time.monotonic()
            try:
                self.collect_once()
                self.ship_if_due(cycle_start)

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
