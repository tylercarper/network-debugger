"""Sample windows: the read model detection rules operate on.

Rules never touch SQL. They receive a :class:`ProbeWindow` -- one probe's samples over a
time range, already grouped by target -- and return events. Keeping rules pure over an
in-memory view is what makes them cheap to test (feed a synthetic sequence, assert the
events) and, crucially, what makes detection **re-runnable over any historical window**.
A rule improved three weeks from now can be replayed over data already stored and produce
better events retroactively.

A ``target`` here is the role label the agent recorded (``gateway``, ``anchor-primary``,
``dns-gateway``), not the raw address -- see the note in the ICMP collector on why samples
are keyed by role.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netdbg_common.enums import SampleKind

__all__ = ["ProbeWindow", "SampleRow", "TargetSeries"]


@dataclass(frozen=True, slots=True)
class SampleRow:
    """One stored sample, as detection sees it.

    ``interval_slip_ms`` and ``ntp_synced`` ride along because they gate trust: a sample
    taken when the probe's own loop was stalled, or when its clock was unsynced, must be
    weighable by a rule rather than taken at face value.
    """

    ts: int
    success: bool
    value_ms: float | None
    code: int | None
    interval_slip_ms: int | None = None
    ntp_synced: bool | None = None


@dataclass(slots=True)
class TargetSeries:
    """All of one probe's samples for one (kind, target) over the window, ts-ascending."""

    kind: SampleKind
    target: str
    rows: list[SampleRow] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rows)

    def success_rate(self) -> float | None:
        """Fraction of samples that succeeded, or None when the series is empty.

        None is deliberately distinct from 0.0: "no data" and "everything failed" are
        different states, and a rule that treated an empty window as a total outage
        would fire on a probe that simply had not reported yet.
        """
        if not self.rows:
            return None
        ok = sum(1 for r in self.rows if r.success)
        return ok / len(self.rows)

    def failures(self) -> list[SampleRow]:
        return [r for r in self.rows if not r.success]

    def rtts(self) -> list[float]:
        """Successful-sample latencies. Failures contribute no timing."""
        return [r.value_ms for r in self.rows if r.success and r.value_ms is not None]


@dataclass(slots=True)
class ProbeWindow:
    """One probe's samples over a time range, grouped by (kind, target).

    The window is the unit of detection: rules are handed one of these and return events.
    ``from_ts``/``to_ts`` bound the range the caller asked for, which a rule needs in
    order to tell "the window ends here" from "the data ends here" -- an ongoing outage
    that runs to the edge of the window has no end yet, and must not be closed off just
    because the window did.
    """

    probe_id: str
    from_ts: int
    to_ts: int
    series: dict[tuple[SampleKind, str], TargetSeries] = field(default_factory=dict)

    def add(self, row: SampleRow, kind: SampleKind, target: str) -> None:
        key = (kind, target)
        s = self.series.get(key)
        if s is None:
            s = TargetSeries(kind=kind, target=target)
            self.series[key] = s
        s.rows.append(row)

    def targets_of(self, kind: SampleKind) -> list[TargetSeries]:
        return [s for (k, _), s in self.series.items() if k == kind]

    def series_for(self, kind: SampleKind, target: str) -> TargetSeries | None:
        return self.series.get((kind, target))

    def all_timestamps(self) -> list[int]:
        """Every distinct sample timestamp in the window, ascending.

        Rules that reason about "the state of everything at moment T" iterate these.
        """
        seen: set[int] = set()
        for s in self.series.values():
            for r in s.rows:
                seen.add(r.ts)
        return sorted(seen)

    def is_empty(self) -> bool:
        return not any(s.rows for s in self.series.values())
