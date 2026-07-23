"""Per-collector cadence scheduling.

Collectors run at different rates: ICMP every second to catch sub-10-second dropouts,
interface state every 5s, DNS every 10s, the HTTP check every 15s. Running the expensive
ones every second would be wasteful and would rate-limit the very services being probed;
running ICMP slowly would miss the brief blips that are the whole point.

A ``ScheduledCollector`` pairs a due-check with a callable. The runner asks each one
"are you due this tick?" and collects only those, so the collectors themselves stay
pure ``(ts) -> Sample`` functions with no notion of time.

Jitter is applied per collector so that N probes on one network do not fire their DNS or
HTTP checks in the same instant -- synchronized bursts would make the probes contend and
distort the measurements they exist to take.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from netdbg_common.models import Sample

__all__ = ["ScheduledCollector"]


@dataclass
class ScheduledCollector:
    """A collector plus its cadence.

    ``collect`` returns a sequence rather than a single Sample so one entry can cover a
    fan-out -- e.g. one DNS collector querying three resolvers -- without the runner
    needing to know how many samples a tick will yield.
    """

    name: str
    interval_s: float
    collect: Callable[[int], Sequence[Sample]]

    # Fraction of the interval to spread firing across, so probes desynchronize.
    jitter_frac: float = 0.1

    _next_due_mono: float = field(default=0.0)
    _rng: random.Random = field(default_factory=random.Random)

    def is_due(self, now_mono: float) -> bool:
        """True when this collector should run, advancing its next-due time if so.

        The first call is always due, so every collector fires once promptly on startup
        rather than waiting a full interval to produce its first sample.
        """
        if now_mono < self._next_due_mono:
            return False
        jitter = self._rng.uniform(0, self.interval_s * self.jitter_frac)
        self._next_due_mono = now_mono + self.interval_s + jitter
        return True

    def run(self, ts: int) -> Sequence[Sample]:
        return self.collect(ts)
