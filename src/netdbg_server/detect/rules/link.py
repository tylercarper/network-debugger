"""Interface link-change detection.

A local link going down is a categorically different diagnosis from the network being
down: it points at the cable, the port, or the adapter -- inside the probe's own machine
-- rather than anything upstream. Recording it distinctly means a correlation later can
say "this probe's outage was just its own cable" and exonerate the rest of the network.
"""

from __future__ import annotations

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.hysteresis import find_spans
from netdbg_server.detect.rules.base import DetectedEvent
from netdbg_server.detect.window import ProbeWindow

__all__ = ["LinkChangeRule"]

# A link flap is worth catching immediately, but a single missed interface sample should
# not register as a down link, so a small hysteresis still applies.
_ENTER = 2
_EXIT = 2


class LinkChangeRule:
    name = "link_change"
    detector_version = 1

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]:
        iface = window.targets_of(SampleKind.IFACE)
        if not iface:
            return []

        events: list[DetectedEvent] = []
        for series in iface:
            # For the interface collector, success == link up. A "bad" point is a down or
            # absent link (absent is recorded with a sentinel code by the collector).
            points = [(r.ts, not r.success) for r in series.rows]
            for span in find_spans(points, enter_consecutive=_ENTER, exit_consecutive=_EXIT):
                # An absent interface (code -1) is distinguished from a present-but-down
                # one -- a vanished adapter vs an unplugged cable.
                absent = any(
                    r.code == -1
                    for r in series.rows
                    if span.started_ts <= r.ts <= (span.ended_ts or window.to_ts) and not r.success
                )
                events.append(
                    DetectedEvent(
                        event_type=EventType.LINK_CHANGE,
                        severity=Severity.CRITICAL,
                        confidence=1.0,  # link state is directly observed, not inferred
                        started_ts=span.started_ts,
                        ended_ts=span.ended_ts,
                        subtype="absent" if absent else "down",
                        evidence={
                            "interface": series.target,
                            "state": "absent" if absent else "down",
                            "detector": self.name,
                        },
                    )
                )
        return events
