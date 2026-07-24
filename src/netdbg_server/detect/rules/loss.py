"""Packet-loss burst detection: partial failure that is not a full outage.

Distinct from an outage on purpose. Total loss (every target down) is a link or backbone
failure; partial loss (some packets dropping while connectivity survives) is RF
contention, a marginal cable, or upstream congestion. Different causes, different fixes --
so they are different events.

This rule looks per-target rather than across all targets: loss to one anchor but not the
other localizes the problem toward that provider's path, which a merged view would hide.
"""

from __future__ import annotations

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.rules.base import DetectedEvent
from netdbg_server.detect.window import ProbeWindow

__all__ = ["LossBurstRule"]

_WINDOW = 30  # samples per sliding evaluation window
_MIN_LOSS_RATE = 0.2  # 20% loss over the window...
_MIN_FAILURES = 3  # ...and at least this many failures, so tiny windows do not trip
_FULL_OUTAGE_RATE = 0.95  # at/above this it is an outage, which OutageRule owns


class LossBurstRule:
    name = "loss_burst"
    detector_version = 1

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]:
        events: list[DetectedEvent] = []
        for series in window.targets_of(SampleKind.ICMP):
            rows = series.rows
            if len(rows) < _WINDOW:
                continue

            # Slide a window across the series and mark stretches of elevated loss. A
            # simple contiguous scan: find where the local loss rate crosses the
            # threshold and stays there.
            in_burst = False
            burst_start = 0
            burst_fail = 0
            burst_total = 0

            i = 0
            while i + _WINDOW <= len(rows):
                chunk = rows[i : i + _WINDOW]
                fails = sum(1 for r in chunk if not r.success)
                rate = fails / _WINDOW

                # A near-total window is an outage, not a loss burst -- yield it to
                # OutageRule and close any burst in progress.
                elevated = _MIN_LOSS_RATE <= rate < _FULL_OUTAGE_RATE and fails >= _MIN_FAILURES

                if elevated and not in_burst:
                    in_burst = True
                    burst_start = chunk[0].ts
                    burst_fail = fails
                    burst_total = _WINDOW
                elif elevated:
                    burst_fail += 1 if not chunk[-1].success else 0
                    burst_total += 1
                elif in_burst:
                    events.append(
                        self._event(
                            series.target, burst_start, chunk[0].ts, burst_fail, burst_total
                        )
                    )
                    in_burst = False
                i += 1

            if in_burst:
                events.append(
                    self._event(series.target, burst_start, None, burst_fail, burst_total)
                )
        return events

    def _event(
        self, target: str, start_ts: int, end_ts: int | None, fails: int, total: int
    ) -> DetectedEvent:
        rate = fails / total if total else 0.0
        return DetectedEvent(
            event_type=EventType.LOSS_BURST,
            severity=Severity.WARN,
            confidence=0.75,
            started_ts=start_ts,
            ended_ts=end_ts,
            evidence={
                "target": target,
                "loss_rate": round(rate, 3),
                "failures": fails,
                "detector": self.name,
            },
        )
