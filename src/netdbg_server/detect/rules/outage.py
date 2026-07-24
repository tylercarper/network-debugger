"""Outage detection: total loss of connectivity from a probe.

An outage is when *everything* fails at once -- the gateway and both external anchors. It
is deliberately distinct from a loss burst (partial failure) and from
gateway-up-internet-down (external-only), because those have different causes and
different fixes. Lumping them together would throw away the distinction that makes the
data actionable.
"""

from __future__ import annotations

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.hysteresis import find_spans
from netdbg_server.detect.rules.base import DetectedEvent
from netdbg_server.detect.window import ProbeWindow

__all__ = ["OutageRule"]

_ENTER = 3  # consecutive all-fail samples to declare an outage
_EXIT = 3  # consecutive all-success samples to clear it


class OutageRule:
    name = "outage"
    detector_version = 1

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]:
        icmp = window.targets_of(SampleKind.ICMP)
        if not icmp:
            return []

        # Build a per-timestamp "was everything failing at this instant" signal. A
        # timestamp counts as bad only when every ICMP target that reported at that
        # instant failed -- a single surviving target means this is not a total outage.
        by_ts: dict[int, list[bool]] = {}
        for series in icmp:
            for row in series.rows:
                by_ts.setdefault(row.ts, []).append(row.success)

        if not by_ts:
            return []

        points = [(ts, not any(successes)) for ts, successes in sorted(by_ts.items())]
        spans = find_spans(points, enter_consecutive=_ENTER, exit_consecutive=_EXIT)

        events: list[DetectedEvent] = []
        for span in spans:
            events.append(
                DetectedEvent(
                    event_type=EventType.OUTAGE,
                    severity=Severity.CRITICAL,
                    confidence=1.0,  # every target down is unambiguous
                    started_ts=span.started_ts,
                    ended_ts=span.ended_ts,
                    evidence={
                        "targets": sorted(s.target for s in icmp),
                        "failed_samples": span.count,
                        "detector": self.name,
                    },
                )
            )
        return events
