"""Detection engine tests, against a real database.

The engine's defining properties are the ones under test here: idempotent re-runs (no
duplicate events), backfill-aware watermarking (late data gets analyzed, not skipped),
and correct persistence of ongoing-then-resolved events. These only mean anything against
real storage, so these tests use a temp SQLite DB rather than a mock.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netdbg_common.enums import LinkType, SampleKind
from netdbg_common.models import ProbeInfo, Sample
from netdbg_server.db.engine import init_db, transaction
from netdbg_server.db.queries import insert_samples, upsert_probe
from netdbg_server.detect.engine import DetectionEngine

NOW = 1_700_000_000_000


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = init_db(tmp_path / "detect.db")
    with transaction(conn):
        upsert_probe(conn, "p1", ProbeInfo(name="probe", link_type=LinkType.WIRED), NOW)
    return conn


def _outage_samples(start: int, count: int, ok: bool) -> list[Sample]:
    """One sample per target per tick -- gateway + both anchors."""
    out: list[Sample] = []
    for i in range(count):
        ts = start + i * 1000
        for target in ("gateway", "anchor-primary", "anchor-secondary"):
            out.append(
                Sample(
                    ts=ts,
                    kind=SampleKind.ICMP,
                    target=target,
                    success=ok,
                    value_ms=5.0 if ok else None,
                )
            )
    return out


def _insert(conn: sqlite3.Connection, samples: list[Sample], recv_ts: int) -> None:
    with transaction(conn):
        insert_samples(conn, "p1", samples, recv_ts)


def _events(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM events ORDER BY started_ts, event_type").fetchall()


# ---------------------------------------------------------------------------
# Basic detection through the DB
# ---------------------------------------------------------------------------


def test_detects_an_outage_from_stored_samples(db: sqlite3.Connection) -> None:
    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    _insert(db, _outage_samples(NOW + 5000, 6, ok=False), NOW + 6000)  # outage
    _insert(db, _outage_samples(NOW + 11000, 5, ok=True), NOW + 12000)

    DetectionEngine().run_incremental(db, "p1", NOW + 20000)

    events = _events(db)
    outages = [e for e in events if e["event_type"] == "outage"]
    assert len(outages) == 1
    assert outages[0]["ended_ts"] is not None, "a resolved outage should have an end"


# ---------------------------------------------------------------------------
# Idempotency -- the property that makes re-runs safe
# ---------------------------------------------------------------------------


def test_rerunning_detection_does_not_duplicate_events(db: sqlite3.Connection) -> None:
    """Running detection twice over the same data must yield the same events.

    This is what lets an improved rule be replayed over stored history. Without upsert on
    (probe_id, event_type, started_ts) each re-run would multiply the events.
    """
    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    _insert(db, _outage_samples(NOW + 5000, 6, ok=False), NOW + 6000)
    _insert(db, _outage_samples(NOW + 11000, 5, ok=True), NOW + 12000)

    engine = DetectionEngine()
    engine.run_probe(db, "p1", NOW, NOW + 20000)
    count_after_first = len(_events(db))
    engine.run_probe(db, "p1", NOW, NOW + 20000)
    count_after_second = len(_events(db))

    assert count_after_first == count_after_second, "re-run duplicated events"
    assert count_after_first >= 1


def test_ongoing_event_is_updated_when_it_later_resolves(db: sqlite3.Connection) -> None:
    """An outage detected while still open must be closed in place once it ends.

    First pass sees an ongoing outage (no end). A later pass, after recovery samples
    arrive, must update that same event with its end -- not create a second one.
    """
    engine = DetectionEngine()

    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    _insert(db, _outage_samples(NOW + 5000, 6, ok=False), NOW + 6000)
    engine.run_incremental(db, "p1", NOW + 11000)  # detect while ongoing

    ongoing = [e for e in _events(db) if e["event_type"] == "outage"]
    assert len(ongoing) == 1
    assert ongoing[0]["ended_ts"] is None, "should be open while the outage continues"

    _insert(db, _outage_samples(NOW + 11000, 5, ok=True), NOW + 12000)  # recovery
    engine.run_incremental(db, "p1", NOW + 20000)

    resolved = [e for e in _events(db) if e["event_type"] == "outage"]
    assert len(resolved) == 1, "resolving the outage created a duplicate instead of updating"
    assert resolved[0]["ended_ts"] is not None


# ---------------------------------------------------------------------------
# Watermark and backfill
# ---------------------------------------------------------------------------


def test_watermark_advances(db: sqlite3.Connection) -> None:
    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    engine = DetectionEngine()
    engine.run_incremental(db, "p1", NOW + 5000)

    assert engine.watermark(db, "p1") == NOW + 5000


def test_backfill_rewinds_watermark_so_late_data_is_detected(db: sqlite3.Connection) -> None:
    """The defining backfill case: an outage's data arrives *after* detection ran past it.

    Detection first runs over a healthy window and advances its watermark. Then the
    outage samples -- which were stuck in the probe's spool during the outage -- arrive
    with older timestamps. Without a rewind they would sit below the watermark and never
    be analyzed. With it, the outage is detected.
    """
    engine = DetectionEngine()

    # Healthy data arrives and is detected; watermark moves past NOW+20000.
    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    _insert(db, _outage_samples(NOW + 15000, 5, ok=True), NOW + 15000)
    engine.run_incremental(db, "p1", NOW + 20000)
    assert not [e for e in _events(db) if e["event_type"] == "outage"], "no outage yet"

    # Now the buffered outage samples arrive -- measured at NOW+5000, but delivered late.
    outage = _outage_samples(NOW + 5000, 6, ok=False)
    _insert(db, outage, recv_ts=NOW + 25000)
    oldest = min(s.ts for s in outage)
    engine.rewind_for_backfill(db, "p1", oldest)

    # Re-run: the rewound watermark reopens the window the backfill landed in.
    engine.run_incremental(db, "p1", NOW + 30000)

    outages = [e for e in _events(db) if e["event_type"] == "outage"]
    assert outages, "backfilled outage was never detected -- rewind failed"
    assert outages[0]["started_ts"] == NOW + 5000


def test_rewind_ignores_data_newer_than_watermark(db: sqlite3.Connection) -> None:
    """Ordinary live data must not needlessly rewind the watermark and redo work."""
    engine = DetectionEngine()
    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    engine.run_incremental(db, "p1", NOW + 5000)

    engine.rewind_for_backfill(db, "p1", NOW + 10000)  # newer than watermark
    assert engine.watermark(db, "p1") == NOW + 5000, "watermark should be unchanged"


# ---------------------------------------------------------------------------
# Multiple probes
# ---------------------------------------------------------------------------


def test_run_all_processes_every_active_probe(db: sqlite3.Connection) -> None:
    with transaction(db):
        upsert_probe(db, "p2", ProbeInfo(name="probe2"), NOW)

    for pid in ("p1", "p2"):
        with transaction(db):
            for target in ("gateway", "anchor-primary", "anchor-secondary"):
                insert_samples(
                    db,
                    pid,
                    [
                        Sample(
                            ts=NOW + i * 1000, kind=SampleKind.ICMP, target=target, success=False
                        )
                        for i in range(6)
                    ],
                    NOW + 6000,
                )

    results = DetectionEngine().run_all(db, NOW + 10000)

    assert {r.probe_id for r in results} == {"p1", "p2"}
    assert all(
        engine_wm is not None
        for engine_wm in (
            DetectionEngine().watermark(db, "p1"),
            DetectionEngine().watermark(db, "p2"),
        )
    )


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_a_broken_rule_does_not_sink_the_pass(db: sqlite3.Connection) -> None:
    """One rule raising must not prevent the others' events from being written."""

    class ExplodingRule:
        name = "boom"
        detector_version = 1

        def detect(self, window: object) -> list[object]:
            raise RuntimeError("kaboom")

    from netdbg_server.detect.rules.outage import OutageRule

    engine = DetectionEngine(rules=[ExplodingRule(), OutageRule()])  # type: ignore[list-item]

    _insert(db, _outage_samples(NOW, 5, ok=True), NOW)
    _insert(db, _outage_samples(NOW + 5000, 6, ok=False), NOW + 6000)
    _insert(db, _outage_samples(NOW + 11000, 5, ok=True), NOW + 12000)

    engine.run_incremental(db, "p1", NOW + 20000)

    assert [e for e in _events(db) if e["event_type"] == "outage"], (
        "the working rule's event was lost because a sibling rule raised"
    )


def test_empty_window_produces_no_events(db: sqlite3.Connection) -> None:
    DetectionEngine().run_incremental(db, "p1", NOW + 5000)
    assert _events(db) == []
