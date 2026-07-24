"""The headline symptom: gateway reachable, internet not.

This is the exact complaint that started the project -- "full bars, but nothing loads".
It is also the detection most prone to false positives, so most of this rule is about
*not* crying wolf.

The condition: over a sliding window the gateway keeps answering while both external
anchors keep failing. The gateway answering is what separates this from a plain outage
(where the gateway fails too) -- the local link and the router are fine; the path to the
world is not.

Two false-positive guards, because ICMP is not trustworthy on its own:

1. **Require both anchors to fail.** One anchor failing could just be that provider
   having a moment. Demanding 1.1.1.1 *and* 8.8.8.8 both fail rules that out.

2. **Cross-check against a non-ICMP signal.** Routers and ISPs routinely rate-limit or
   drop ICMP to their control plane, so ping to 1.1.1.1 can fail while real traffic
   flows. If an HTTP check *succeeds* during the same window, the internet is actually
   up and ICMP is merely filtered -- so this downgrades to a low-severity ``icmp_filtered``
   finding instead of asserting an outage. This guard is the single most important reason
   the rule is trustworthy, and #14 tracks it explicitly.
"""

from __future__ import annotations

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_server.detect.hysteresis import find_spans
from netdbg_server.detect.rules.base import DetectedEvent
from netdbg_server.detect.window import ProbeWindow

__all__ = ["GatewayUpInternetDownRule"]

_ENTER = 3
_EXIT = 3
_GATEWAY = "gateway"
# HTTP sample codes (mirrors http_probe): 204 clean, 1 captive portal. Either means bytes
# actually flowed, so the internet is up regardless of what ICMP reported.
_HTTP_OK_CODES = frozenset({204, 1})


class GatewayUpInternetDownRule:
    name = "gateway_up_internet_down"
    detector_version = 1

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]:
        gw = window.series_for(SampleKind.ICMP, _GATEWAY)
        if gw is None:
            # Without a gateway series we cannot assert the gateway is up, so we cannot
            # make this specific claim at all. A different rule (outage) still fires.
            return []

        anchors = [s for s in window.targets_of(SampleKind.ICMP) if s.target.startswith("anchor")]
        if not anchors:
            return []

        gw_ok = {r.ts: r.success for r in gw.rows}
        anchor_by_ts: dict[int, list[bool]] = {}
        for series in anchors:
            for row in series.rows:
                anchor_by_ts.setdefault(row.ts, []).append(row.success)

        # The condition at instant T: gateway succeeded AND every anchor that reported at
        # T failed. Only timestamps where both the gateway and at least one anchor
        # reported are considered -- otherwise a gap in one series would be misread.
        points: list[tuple[int, bool]] = []
        for ts in sorted(gw_ok.keys() & anchor_by_ts.keys()):
            gateway_up = gw_ok[ts]
            all_anchors_down = not any(anchor_by_ts[ts])
            points.append((ts, gateway_up and all_anchors_down))

        if not points:
            return []

        spans = find_spans(points, enter_consecutive=_ENTER, exit_consecutive=_EXIT)
        if not spans:
            return []

        events: list[DetectedEvent] = []
        for span in spans:
            http_up = self._http_succeeded_during(window, span.started_ts, span.ended_ts)

            if http_up:
                # Guard #2 fired: bytes flowed over HTTP during the "outage", so ICMP was
                # merely filtered. Report the truth at low severity, not an outage.
                events.append(
                    DetectedEvent(
                        event_type=EventType.ICMP_FILTERED,
                        severity=Severity.INFO,
                        confidence=0.6,
                        started_ts=span.started_ts,
                        ended_ts=span.ended_ts,
                        subtype="anchors_icmp_only",
                        evidence={
                            "note": "ICMP to anchors failed but HTTP succeeded; "
                            "internet is up, ICMP is being filtered",
                            "failed_samples": span.count,
                            "detector": self.name,
                        },
                    )
                )
                continue

            # No contradicting HTTP success -> assert the real thing.
            dns_all_failed = self._dns_all_failed_during(window, span.started_ts, span.ended_ts)
            subtype = "dns_and_reachability" if dns_all_failed else "reachability"
            events.append(
                DetectedEvent(
                    event_type=EventType.GATEWAY_UP_INTERNET_DOWN,
                    severity=Severity.CRITICAL,
                    # High but not certain: without a positive non-ICMP failure signal we
                    # cannot fully exclude asymmetric ICMP filtering.
                    confidence=0.85 if dns_all_failed else 0.75,
                    started_ts=span.started_ts,
                    ended_ts=span.ended_ts,
                    subtype=subtype,
                    evidence={
                        "gateway": "up",
                        "anchors": "all_down",
                        "dns_all_failed": dns_all_failed,
                        "failed_samples": span.count,
                        "detector": self.name,
                    },
                )
            )
        return events

    def _http_succeeded_during(
        self, window: ProbeWindow, start_ts: int, end_ts: int | None
    ) -> bool:
        """Did any HTTP check confirm bytes flowing during the span?

        When the span is still open (end None), the check runs to the window edge.
        """
        hi = end_ts if end_ts is not None else window.to_ts
        for series in window.targets_of(SampleKind.HTTP):
            for row in series.rows:
                if start_ts <= row.ts <= hi and row.success and row.code in _HTTP_OK_CODES:
                    return True
        return False

    def _dns_all_failed_during(
        self, window: ProbeWindow, start_ts: int, end_ts: int | None
    ) -> bool:
        """Did every DNS query in the span fail? Sub-classifies the event, not gates it.

        Requires at least one DNS sample in the span -- "no DNS data" is not "DNS failed".
        """
        hi = end_ts if end_ts is not None else window.to_ts
        saw_any = False
        for series in window.targets_of(SampleKind.DNS):
            for row in series.rows:
                if start_ts <= row.ts <= hi:
                    saw_any = True
                    if row.success:
                        return False
        return saw_any
