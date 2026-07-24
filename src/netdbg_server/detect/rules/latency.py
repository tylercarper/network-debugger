"""Latency spike detection, relative to each probe's own baseline.

The threshold is per-probe, not absolute, because "normal" latency legitimately differs
between vantage points: a wired Pi at the router and a WiFi probe two rooms away have
different baselines, and a fixed threshold would either miss real spikes on the fast probe
or cry wolf constantly on the slow one.

The baseline is the median of successful RTTs in the window itself. That is a simplifying
choice for now -- a longer-horizon baseline from the rollup tables would be more robust --
but the median is resistant to the very spikes being detected, so it does not poison
itself the way a mean would.
"""

from __future__ import annotations

import statistics

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.hysteresis import find_spans
from netdbg_server.detect.rules.base import DetectedEvent
from netdbg_server.detect.window import ProbeWindow

__all__ = ["LatencySpikeRule"]

_ENTER = 5  # spikes need more confirmation than outages -- latency is noisier
_EXIT = 5
_MULTIPLIER = 3.0  # RTT above 3x baseline is a spike...
_FLOOR_MS = 50.0  # ...but at least this far above it, so tiny baselines do not overreact
_MIN_SAMPLES = 10  # need enough successful samples for a meaningful baseline


class LatencySpikeRule:
    name = "latency_spike"
    detector_version = 1

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]:
        events: list[DetectedEvent] = []
        # Only external anchors: gateway RTT is sub-millisecond and its spikes are a
        # different phenomenon (local contention), better handled separately.
        for series in window.targets_of(SampleKind.ICMP):
            if not series.target.startswith("anchor"):
                continue
            rtts = series.rtts()
            if len(rtts) < _MIN_SAMPLES:
                continue

            baseline = statistics.median(rtts)
            threshold = max(baseline * _MULTIPLIER, baseline + _FLOOR_MS)

            # A point is "bad" when a successful sample's RTT exceeds the threshold.
            # Failed samples are not spikes -- they are loss, a different rule's concern.
            points = [
                (r.ts, r.success and r.value_ms is not None and r.value_ms > threshold)
                for r in series.rows
            ]
            for span in find_spans(points, enter_consecutive=_ENTER, exit_consecutive=_EXIT):
                spike_rtts = [
                    r.value_ms
                    for r in series.rows
                    if r.value_ms is not None
                    and span.started_ts <= r.ts <= (span.ended_ts or window.to_ts)
                    and r.value_ms > threshold
                ]
                events.append(
                    DetectedEvent(
                        event_type=EventType.LATENCY_SPIKE,
                        severity=Severity.WARN,
                        confidence=0.8,
                        started_ts=span.started_ts,
                        ended_ts=span.ended_ts,
                        evidence={
                            "target": series.target,
                            "baseline_ms": round(baseline, 1),
                            "threshold_ms": round(threshold, 1),
                            "peak_ms": round(max(spike_rtts), 1) if spike_rtts else None,
                            "detector": self.name,
                        },
                    )
                )
        return events
