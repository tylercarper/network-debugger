"""Tests for the monotonic-anchored clock.

The scenarios that matter are the ones that corrupt timestamps in ways nothing
downstream can detect: NTP steps, wake-from-sleep, and backwards jumps. Each is
simulated through an injectable time source rather than by patching global time.
"""

from __future__ import annotations

from netdbg_common.timeutil import DEFAULT_STEP_THRESHOLD_MS, ClockStep, MonotonicClock


class FakeTime:
    """Independently controllable wall and monotonic clocks.

    Keeping them independent is the whole point: the failure modes under test are
    exactly those where wall clock moves and monotonic does not, or vice versa.
    """

    def __init__(self, wall: int = 1_700_000_000_000, mono: int = 10_000) -> None:
        self._wall = wall
        self._mono = mono

    def wall_ms(self) -> int:
        return self._wall

    def monotonic_ms(self) -> int:
        return self._mono

    def advance(self, ms: int) -> None:
        """Normal time passing: both clocks move together."""
        self._wall += ms
        self._mono += ms

    def step_wall(self, ms: int) -> None:
        """NTP correction: wall clock jumps, monotonic is unaffected."""
        self._wall += ms

    def suspend(self, ms: int) -> None:
        """Host sleeps: wall clock advances, monotonic (mostly) does not."""
        self._wall += ms


def test_now_ms_tracks_normal_time() -> None:
    t = FakeTime()
    clock = MonotonicClock(source=t)
    start = clock.now_ms()
    t.advance(5_000)
    assert clock.now_ms() == start + 5_000


def test_forward_ntp_step_does_not_corrupt_timestamps() -> None:
    """A forward NTP step must not make derived time leap.

    This is the core guarantee: between two measurements one second apart, the reported
    timestamps must differ by ~one second even if the wall clock jumped 30s in between.
    Otherwise samples land in the wrong place in the timeline.
    """
    t = FakeTime()
    clock = MonotonicClock(source=t)

    t.advance(1_000)
    before = clock.now_ms()

    t.step_wall(30_000)  # NTP resync jumps the wall clock forward
    t.advance(1_000)
    after = clock.now_ms()

    # Derived time advanced by the real elapsed second, not by the 30s step.
    assert after - before == 1_000


def test_backwards_step_never_moves_timestamps_backwards() -> None:
    """Timestamps must be monotonically non-decreasing.

    A backwards wall-clock correction would otherwise produce samples that appear to
    precede earlier ones, which corrupts ordering and any windowed detection over them.
    """
    t = FakeTime()
    clock = MonotonicClock(source=t)

    readings = [clock.now_ms()]
    for _ in range(3):
        t.advance(500)
        readings.append(clock.now_ms())

    t.step_wall(-60_000)  # wall clock corrected backwards by a minute
    t.advance(500)
    readings.append(clock.now_ms())

    assert readings == sorted(readings), "timestamps went backwards"


def test_check_step_detects_and_records_forward_step() -> None:
    t = FakeTime()
    clock = MonotonicClock(source=t)

    t.advance(1_000)
    assert clock.check_step() is None, "ordinary elapsed time is not a step"

    t.step_wall(30_000)
    step = clock.check_step()

    assert step is not None
    assert step.delta_ms == 30_000
    assert clock.steps == [step]


def test_check_step_ignores_sub_threshold_drift() -> None:
    """Ordinary clock drift must not generate a storm of clock_step events."""
    t = FakeTime()
    clock = MonotonicClock(source=t)

    t.advance(10_000)
    t.step_wall(DEFAULT_STEP_THRESHOLD_MS - 1)

    assert clock.check_step() is None
    assert clock.steps == []


def test_reanchor_after_step_tracks_corrected_wall_clock() -> None:
    """After a step, derived time should follow the corrected clock, not the stale anchor.

    The post-step wall clock is the better estimate of true time; continuing to derive
    from the old anchor would preserve a known-wrong offset indefinitely.
    """
    t = FakeTime()
    clock = MonotonicClock(source=t)

    t.advance(1_000)
    t.step_wall(30_000)
    clock.check_step()

    t.advance(2_000)
    assert clock.now_ms() == t.wall_ms()


def test_suspend_is_distinguished_from_ntp_step() -> None:
    """Wake-from-sleep must be identifiable, not just detected.

    A sleeping probe generates a gap that looks exactly like a total outage. Detection
    suppresses outages spanning a suspend, so the two causes must be distinguishable:
    during suspend the wall clock advances while monotonic does not.
    """
    t = FakeTime()
    clock = MonotonicClock(source=t)

    t.advance(1_000)
    clock.check_step()

    t.suspend(3_600_000)  # an hour asleep; monotonic did not advance
    step = clock.check_step()

    assert step is not None
    assert step.likely_suspend, "a wall-clock-only jump should be classified as suspend"


def test_ntp_step_is_not_misread_as_suspend() -> None:
    """The converse: a step while the process ran normally is not a suspend."""
    t = FakeTime()
    clock = MonotonicClock(source=t)

    t.advance(60_000)  # process running normally; both clocks advance
    clock.check_step()
    t.advance(1_000)  # a full polling interval elapsed on both clocks
    t.step_wall(5_000)  # ...then NTP corrected forward by 5s
    step = clock.check_step()

    assert step is not None
    assert not step.likely_suspend, "a step while the process kept running is not a suspend"


def test_on_step_callback_fires() -> None:
    """The agent hooks this to emit a clock_step event into the spool."""
    t = FakeTime()
    seen: list[ClockStep] = []
    clock = MonotonicClock(source=t, on_step=seen.append)

    t.advance(1_000)
    t.step_wall(10_000)
    clock.check_step()

    assert len(seen) == 1
    assert seen[0].delta_ms == 10_000


def test_timestamps_are_plausible_epoch_ms() -> None:
    """Guard against unit mix-ups (seconds vs ms), which are silent and corrupting."""
    clock = MonotonicClock()
    now = clock.now_ms()
    assert 1_600_000_000_000 < now < 2_500_000_000_000
