"""Hysteresis tests.

The edges are where this logic earns its keep: a single blip must not open an event, a
brief recovery must not split one, and an ongoing condition at the window edge must report
no end. Each is a distinct failure mode that would either flood the user with phantom
events or corrupt the timeline.
"""

from __future__ import annotations

from netdbg_server.detect.hysteresis import find_spans


def _pts(pattern: str) -> list[tuple[int, bool]]:
    """'G'ood/'B'ad string -> (ts, is_bad) points, one per second."""
    return [(i * 1000, c == "B") for i, c in enumerate(pattern)]


def test_clean_sequence_has_no_spans() -> None:
    assert find_spans(_pts("GGGGGGGG")) == []


def test_single_blip_does_not_enter() -> None:
    """One failed sample is noise, not an event.

    Without entry hysteresis a marginal link would generate an event per dropped packet.
    """
    assert find_spans(_pts("GGBGGBGG")) == []


def test_sustained_failure_produces_one_span() -> None:
    spans = find_spans(_pts("GGGBBBBGGG"))
    assert len(spans) == 1
    assert spans[0].started_ts == 3000
    assert spans[0].ended_ts == 6000


def test_span_starts_at_first_failure_not_at_confirmation() -> None:
    """The outage began when the failures began, not when the rule became sure.

    Reporting the third failure as the start would systematically under-report every
    outage's duration.
    """
    spans = find_spans(_pts("BBBBGGGG"))
    assert spans[0].started_ts == 0, "start should be the first bad sample"


def test_brief_recovery_does_not_split_an_outage() -> None:
    """A single good sample mid-outage is a flap, not a recovery.

    Exit hysteresis keeps it one event. Splitting would turn one 30-second outage into
    three, misrepresenting both count and duration.
    """
    spans = find_spans(_pts("BBBBGBBBBGGGG"))
    assert len(spans) == 1
    assert spans[0].started_ts == 0
    assert spans[0].ended_ts == 8000


def test_full_recovery_closes_the_span() -> None:
    spans = find_spans(_pts("BBBBGGGGBBBB"))
    assert len(spans) == 2


def test_ongoing_at_window_edge_has_no_end() -> None:
    """A condition still true at the last sample is not over.

    Reporting an end at the window edge would close an outage that is still happening.
    """
    spans = find_spans(_pts("GGGBBBB"))
    assert spans[0].ended_ts is None


def test_configurable_thresholds() -> None:
    """A slow-sampled signal (e.g. DNS at 10s) needs fewer confirmations."""
    # With enter=2, two bad samples are enough.
    assert len(find_spans(_pts("GGBBGG"), enter_consecutive=2, exit_consecutive=2)) == 1
    # With the default enter=3, the same two are not.
    assert find_spans(_pts("GGBBGG")) == []


def test_count_reflects_bad_samples() -> None:
    spans = find_spans(_pts("GGBBBBBGG"))
    assert spans[0].count == 5


def test_empty_input() -> None:
    assert find_spans([]) == []
