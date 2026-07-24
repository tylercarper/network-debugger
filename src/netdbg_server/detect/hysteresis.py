"""Hysteresis state-machine over a boolean-per-timestamp condition.

Detection rules share a shape: walk a time-ordered sequence of "is the bad thing true at
this instant", and emit an event spanning the stretch where it stayed true. The subtlety
is at the edges. A single failed sample must not open an event, and a single success in
the middle of an outage must not close one -- a marginal link flapping on the threshold
would otherwise produce a storm of tiny events that buries the real one.

So entry and exit each require N consecutive confirmations. This trades a few seconds of
detection latency for precision, which is the right trade when diagnosing a problem that
recurs over weeks: a missed 2-second blip costs little, but a hundred phantom events
destroy trust in the tool. The raw samples are retained regardless, so a lower-threshold
rule can be re-run later if the blips turn out to matter.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

__all__ = ["Span", "find_spans"]


@dataclass(frozen=True, slots=True)
class Span:
    """A confirmed stretch where the condition held.

    ``ended_ts`` is None when the condition was still true at the end of the input --
    i.e. an ongoing event that runs to the edge of the window and has no end yet.
    ``peak`` and ``count`` summarize the span for evidence.
    """

    started_ts: int
    ended_ts: int | None
    count: int


@dataclass(frozen=True, slots=True)
class _Point:
    ts: int
    bad: bool


def find_spans(
    points: Sequence[tuple[int, bool]],
    enter_consecutive: int = 3,
    exit_consecutive: int = 3,
) -> list[Span]:
    """Find spans where ``bad`` stayed true, with entry/exit hysteresis.

    ``points`` is (timestamp, is-bad) in ascending time order. A span opens after
    ``enter_consecutive`` consecutive bad points and closes after ``exit_consecutive``
    consecutive good ones. The span's ``started_ts`` is the *first* bad point of the
    entering run, not the point at which entry was confirmed -- the outage began when the
    failures began, not when the rule became sure of it. Likewise its ``ended_ts`` is the
    last bad point, not the confirming good one.
    """
    pts = [_Point(ts, bad) for ts, bad in points]
    spans: list[Span] = []

    in_span = False
    span_start_ts: int | None = None
    last_bad_ts: int | None = None
    span_count = 0

    i = 0
    n = len(pts)
    while i < n:
        # Measure the length of the consecutive run of equal `bad` starting at i.
        j = i
        while j < n and pts[j].bad == pts[i].bad:
            j += 1
        run_len = j - i
        run_is_bad = pts[i].bad

        if not in_span:
            if run_is_bad and run_len >= enter_consecutive:
                in_span = True
                span_start_ts = pts[i].ts
                last_bad_ts = pts[j - 1].ts
                span_count = run_len
            # A bad run too short to enter is ignored -- that is the entry hysteresis.
        else:
            if run_is_bad:
                last_bad_ts = pts[j - 1].ts
                span_count += run_len
            elif run_len >= exit_consecutive:
                # Enough good samples to close the span. It ended at the last bad point.
                assert span_start_ts is not None
                spans.append(Span(started_ts=span_start_ts, ended_ts=last_bad_ts, count=span_count))
                in_span = False
                span_start_ts = None
                span_count = 0
            # A good run too short to exit is swallowed into the ongoing span -- exit
            # hysteresis -- and does not reset last_bad_ts.

        i = j

    if in_span:
        assert span_start_ts is not None
        # Ongoing at the window edge: no confirmed end. Report ended_ts=None so the
        # engine leaves the event open and updates it when a later window sees it close.
        spans.append(Span(started_ts=span_start_ts, ended_ts=None, count=span_count))

    return spans
