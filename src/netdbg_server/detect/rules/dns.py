"""DNS failure detection, keyed on resolver asymmetry.

The interesting signal is *which* resolvers fail. If the gateway's resolver fails while
public resolvers answer, the router's DNS forwarder is the fault -- a common, specific,
fixable cause of "connected but nothing loads". If every resolver fails while ICMP still
works, the problem is upstream or DNS is being filtered. A rule that only asked "did DNS
fail" would collapse those two very different diagnoses into one.
"""

from __future__ import annotations

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.hysteresis import find_spans
from netdbg_server.detect.rules.base import DetectedEvent
from netdbg_server.detect.window import ProbeWindow

__all__ = ["DnsFailureRule"]

_ENTER = 2  # DNS is sampled slowly (10s), so 2 consecutive failures is already ~20s
_EXIT = 2


class DnsFailureRule:
    name = "dns_failure"
    detector_version = 1

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]:
        dns = window.targets_of(SampleKind.DNS)
        if not dns:
            return []

        events: list[DetectedEvent] = []
        for series in dns:
            points = [(r.ts, not r.success) for r in series.rows]
            for span in find_spans(points, enter_consecutive=_ENTER, exit_consecutive=_EXIT):
                is_gateway_resolver = series.target == "dns-gateway"
                # Whether other resolvers were healthy during this span decides the
                # diagnosis: gateway-only failure points at the router's forwarder.
                others_ok = self._other_resolvers_ok(
                    window, series.target, span.started_ts, span.ended_ts
                )
                if is_gateway_resolver and others_ok:
                    subtype = "router_forwarder"
                    severity = Severity.WARN
                elif not others_ok:
                    subtype = "all_resolvers"
                    severity = Severity.CRITICAL
                else:
                    subtype = "single_resolver"
                    severity = Severity.INFO

                events.append(
                    DetectedEvent(
                        event_type=EventType.DNS_FAILURE,
                        severity=severity,
                        confidence=0.8,
                        started_ts=span.started_ts,
                        ended_ts=span.ended_ts,
                        subtype=subtype,
                        evidence={
                            "resolver": series.target,
                            "other_resolvers_ok": others_ok,
                            "failed_samples": span.count,
                            "detector": self.name,
                        },
                    )
                )
        return events

    def _other_resolvers_ok(
        self, window: ProbeWindow, this_target: str, start_ts: int, end_ts: int | None
    ) -> bool:
        """Did any *other* resolver succeed during the span?

        True means the fault is local to ``this_target``; False means it was widespread.
        """
        hi = end_ts if end_ts is not None else window.to_ts
        for series in window.targets_of(SampleKind.DNS):
            if series.target == this_target:
                continue
            for row in series.rows:
                if start_ts <= row.ts <= hi and row.success:
                    return True
        return False
