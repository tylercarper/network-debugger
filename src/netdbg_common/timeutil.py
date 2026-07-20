"""Monotonic-anchored UTC clock.

Measurement timestamps must survive two hazards that naive ``time.time()`` does not:

1. **Queueing.** A sample taken during an outage may sit in the spool for hours. Its
   timestamp must reflect when it was *measured*, never when it was received. That is
   handled by stamping at measurement and treating ``ts`` as immutable downstream.

2. **Wall-clock jumps.** ``time.time()`` can leap forwards or backwards when NTP steps
   the clock after a resync, or when a machine wakes from sleep and corrects. A sample
   stamped mid-jump is wrong even with an empty queue, and on a probe that sleeps it
   fabricates a flawless-looking outage.

This module addresses (2) by anchoring wall clock to ``time.monotonic()`` once, then
deriving every subsequent timestamp from monotonic elapsed time. Monotonic never jumps
and never runs backwards, so derived timestamps advance smoothly across an NTP step.

The tradeoff: derived time slowly diverges from true wall clock as the anchor ages
(clock drift, typically <1s/day). We therefore re-anchor whenever observed divergence
exceeds a threshold, and record a :class:`ClockStep` so samples near the discontinuity
can be distrusted rather than silently believed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

__all__ = ["ClockStep", "MonotonicClock", "utc_now_ms"]

# Divergence between wall clock and monotonic-derived time beyond which we assume the
# wall clock stepped rather than drifted. NTP slews small corrections gradually and
# steps large ones; 1s comfortably separates ordinary drift from a real step.
DEFAULT_STEP_THRESHOLD_MS = 1_000

# The interval at which the agent runner is expected to call ``check_step``. Used only
# to tell a suspend (monotonic stalls well below this) from an NTP step (monotonic
# advances roughly this much because the process kept running).
DEFAULT_CHECK_INTERVAL_MS = 1_000


class _TimeSource(Protocol):
    """Injectable clock pair, so tests can simulate steps without patching globals."""

    def wall_ms(self) -> int: ...
    def monotonic_ms(self) -> int: ...


class _SystemTime:
    def wall_ms(self) -> int:
        return int(time.time() * 1000)

    def monotonic_ms(self) -> int:
        return int(time.monotonic() * 1000)


@dataclass(frozen=True, slots=True)
class ClockStep:
    """A detected wall-clock discontinuity.

    ``delta_ms`` is (observed wall clock - derived time): positive means the wall clock
    jumped forward. A large positive delta on a laptop most often means wake-from-sleep,
    which is why detecting this is what stops a sleeping probe from reporting a phantom
    outage covering the sleep interval.
    """

    detected_at_ms: int
    delta_ms: int
    monotonic_gap_ms: int
    """Monotonic time elapsed since the previous check."""

    expected_gap_ms: int
    """How long the caller expected between checks (its polling interval).

    This is what separates the two causes. Under an NTP step the process keeps running,
    so monotonic advances by roughly the polling interval. Under suspend, monotonic
    stalls (it does not count sleep on macOS or Windows), so the gap comes in far below
    the expected interval while the wall clock leaps ahead. Comparing the monotonic gap
    against ``delta_ms`` instead would misclassify any step larger than the polling
    interval as a suspend.
    """

    @property
    def likely_suspend(self) -> bool:
        """True when monotonic stalled while wall clock advanced — i.e. the host slept.

        Requires a forward wall-clock jump *and* a monotonic gap well below the expected
        polling interval. Both conditions matter: the first rules out backwards NTP
        corrections, the second rules out ordinary forward steps.
        """
        stalled = self.monotonic_gap_ms < self.expected_gap_ms // 2
        return self.delta_ms > 0 and stalled


class MonotonicClock:
    """Produces UTC epoch-millisecond timestamps that are immune to wall-clock jumps.

    Every timestamp is ``anchor_wall + (monotonic_now - anchor_monotonic)``. Call
    :meth:`now_ms` to stamp a measurement; call :meth:`check_step` periodically (the
    agent runner does this each cycle) to detect and record discontinuities.
    """

    def __init__(
        self,
        source: _TimeSource | None = None,
        step_threshold_ms: int = DEFAULT_STEP_THRESHOLD_MS,
        on_step: Callable[[ClockStep], None] | None = None,
        expected_check_interval_ms: int = DEFAULT_CHECK_INTERVAL_MS,
    ) -> None:
        self._source = source or _SystemTime()
        self._step_threshold_ms = step_threshold_ms
        self._on_step = on_step
        self._expected_check_interval_ms = expected_check_interval_ms
        self._anchor_wall_ms = self._source.wall_ms()
        self._anchor_mono_ms = self._source.monotonic_ms()
        self._last_check_mono_ms = self._anchor_mono_ms
        self._steps: list[ClockStep] = []

    def now_ms(self) -> int:
        """Current UTC epoch milliseconds, derived from the monotonic anchor."""
        elapsed = self._source.monotonic_ms() - self._anchor_mono_ms
        return self._anchor_wall_ms + elapsed

    def check_step(self) -> ClockStep | None:
        """Detect a wall-clock discontinuity; re-anchor and record one if found.

        Returns the :class:`ClockStep` when a step is detected, else ``None``. Safe and
        cheap to call frequently.
        """
        observed_wall = self._source.wall_ms()
        mono_now = self._source.monotonic_ms()
        derived = self._anchor_wall_ms + (mono_now - self._anchor_mono_ms)
        delta = observed_wall - derived

        if abs(delta) < self._step_threshold_ms:
            self._last_check_mono_ms = mono_now
            return None

        step = ClockStep(
            detected_at_ms=observed_wall,
            delta_ms=delta,
            monotonic_gap_ms=mono_now - self._last_check_mono_ms,
            expected_gap_ms=self._expected_check_interval_ms,
        )
        # Re-anchor to the observed wall clock: it is now the better estimate of true
        # time, and continuing to derive from a stale anchor would compound the error.
        self._anchor_wall_ms = observed_wall
        self._anchor_mono_ms = mono_now
        self._last_check_mono_ms = mono_now
        self._steps.append(step)
        if self._on_step is not None:
            self._on_step(step)
        return step

    @property
    def steps(self) -> list[ClockStep]:
        """All discontinuities detected so far, oldest first."""
        return list(self._steps)

    @property
    def anchor_age_ms(self) -> int:
        """Monotonic time since the current anchor was set.

        Drift accumulates with anchor age, so a very old anchor is a mild quality signal.
        """
        return self._source.monotonic_ms() - self._anchor_mono_ms


_default_clock = MonotonicClock()


def utc_now_ms() -> int:
    """Module-level convenience stamp from the process-wide default clock."""
    return _default_clock.now_ms()
