"""Storage layer tests.

Two concerns get most of the attention: that measurement timestamps survive a round trip
unaltered, and that the indexes are actually *used* by the queries they exist for. The
second matters because an unused index looks identical to a used one until the table has
a million rows on a Pi.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netdbg_common.enums import EventType, LinkType, ProbeStatus, SampleKind, Severity
from netdbg_common.models import Event, ProbeInfo, Sample, WifiSample
from netdbg_server.db.engine import connect_readonly, init_db, transaction
from netdbg_server.db.queries import (
    get_or_create_target,
    get_probe,
    insert_events,
    insert_samples,
    insert_wifi_samples,
    list_probes,
    record_batch,
    touch_probe_seen,
    upsert_probe,
)

NOW = 1_700_000_000_000


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = init_db(tmp_path / "test.db")
    with transaction(conn):
        upsert_probe(conn, "probe-a", ProbeInfo(name="pi-wired", link_type=LinkType.WIRED), NOW)
    return conn


# ---------------------------------------------------------------------------
# Pragmas
# ---------------------------------------------------------------------------


def test_wal_mode_enabled(db: sqlite3.Connection) -> None:
    """WAL is what lets the dashboard and analysis agent read during ingest."""
    assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_foreign_keys_enforced(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError), transaction(db):
        db.execute(
            "INSERT INTO samples (probe_id, ts, recv_ts, kind, target_id, success)"
            " VALUES ('nonexistent-probe', 1, 1, 1, 1, 1)"
        )


def test_pragmas_survive_init(db: sqlite3.Connection) -> None:
    """executescript can reset pragmas, so init_db reasserts them afterwards."""
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_init_db_is_idempotent(tmp_path: Path) -> None:
    """Called on every server start, so a second run must not fail or lose data."""
    path = tmp_path / "twice.db"
    conn = init_db(path)
    with transaction(conn):
        upsert_probe(conn, "p1", ProbeInfo(name="first"), NOW)
    conn.close()

    conn2 = init_db(path)
    assert get_probe(conn2, "p1") is not None


# ---------------------------------------------------------------------------
# Timestamp integrity -- the core invariant
# ---------------------------------------------------------------------------


def test_measurement_ts_is_stored_unmodified(db: sqlite3.Connection) -> None:
    """A six-hour-old backfilled sample must keep its original measurement time.

    This is the invariant the whole design rests on: an outage is exactly when the
    server is unreachable, so samples routinely arrive long after measurement. If
    storage nudged ``ts`` toward arrival time, every outage would be recorded at the
    moment connectivity *returned* rather than when it broke.
    """
    measured_at = NOW
    received_at = NOW + 6 * 3_600_000

    with transaction(db):
        insert_samples(
            db,
            "probe-a",
            [Sample(ts=measured_at, kind=SampleKind.ICMP, target="1.1.1.1", success=False)],
            recv_ts=received_at,
        )

    row = db.execute("SELECT ts, recv_ts FROM samples").fetchone()
    assert row["ts"] == measured_at
    assert row["recv_ts"] == received_at
    assert row["recv_ts"] - row["ts"] == 6 * 3_600_000


def test_out_of_order_timestamps_accepted(db: sqlite3.Connection) -> None:
    """Backfill interleaves with live data; storage must not require ordering."""
    with transaction(db):
        insert_samples(
            db,
            "probe-a",
            [
                Sample(ts=NOW + 5000, kind=SampleKind.ICMP, target="gw", success=True),
                Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True),
                Sample(ts=NOW + 2000, kind=SampleKind.ICMP, target="gw", success=True),
            ],
            recv_ts=NOW + 10_000,
        )

    stored = [r["ts"] for r in db.execute("SELECT ts FROM samples ORDER BY ts")]
    assert stored == [NOW, NOW + 2000, NOW + 5000]


def test_touch_probe_seen_uses_server_time(db: sqlite3.Connection) -> None:
    """last_seen_ts answers "when did we last hear from this probe".

    It must track server time. Using agent time would make a backfill of old samples
    look like a fresh check-in, which would defeat probe_silence detection.
    """
    with transaction(db):
        touch_probe_seen(db, "probe-a", now_ms=NOW + 60_000, offset_ms=-250)

    probe = get_probe(db, "probe-a")
    assert probe is not None
    assert probe.last_seen_ts == NOW + 60_000
    assert probe.clock_offset_ms == -250


def test_registration_does_not_set_last_seen(db: sqlite3.Connection) -> None:
    """Registering is not reporting.

    A probe that registers and then goes silent -- never shipping a single sample --
    must stay distinguishable from a healthy one. That gap is exactly what
    probe_silence detection looks for, so only an actual ingest may advance
    last_seen_ts.
    """
    probe = get_probe(db, "probe-a")
    assert probe is not None
    assert probe.last_seen_ts is None, "registration must not count as reporting"

    with transaction(db):
        upsert_probe(db, "probe-a", ProbeInfo(name="pi-wired"), NOW + 60_000)

    probe = get_probe(db, "probe-a")
    assert probe is not None
    assert probe.last_seen_ts is None, "re-registration must not count either"


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


def test_reregistration_preserves_admin_fields(db: sqlite3.Connection) -> None:
    """An agent restart must not undo a rename done in the admin UI."""
    with transaction(db):
        db.execute(
            "UPDATE probes SET display_name = ?, group_name = ?, location = ?"
            " WHERE probe_id = 'probe-a'",
            ("Living Room Pi", "ap-living-room", "shelf by TV"),
        )

    with transaction(db):
        upsert_probe(
            db,
            "probe-a",
            ProbeInfo(name="pi-wired", link_type=LinkType.WIRED, os_name="Linux"),
            NOW,
        )

    probe = get_probe(db, "probe-a")
    assert probe is not None
    assert probe.display_name == "Living Room Pi"
    assert probe.group_name == "ap-living-room"
    assert probe.effective_name == "Living Room Pi"


def test_capabilities_roundtrip(db: sqlite3.Connection) -> None:
    """Capabilities drive graceful degradation, so they must survive storage."""
    with transaction(db):
        upsert_probe(
            db,
            "probe-mac",
            ProbeInfo(name="macbook", capabilities=["wifi.rssi", "icmp.privileged"]),
            NOW,
        )

    probe = get_probe(db, "probe-mac")
    assert probe is not None
    assert probe.capabilities == ["wifi.rssi", "icmp.privileged"]


def test_list_probes_excludes_retired_by_default(db: sqlite3.Connection) -> None:
    with transaction(db):
        upsert_probe(db, "old", ProbeInfo(name="retired-probe"), NOW, status=ProbeStatus.RETIRED)

    assert [p.probe_id for p in list_probes(db)] == ["probe-a"]
    assert len(list_probes(db, include_retired=True)) == 2


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def test_target_is_deduplicated(db: sqlite3.Connection) -> None:
    """The lookup table exists to avoid repeating '1.1.1.1' millions of times."""
    with transaction(db):
        first = get_or_create_target(db, SampleKind.ICMP, "1.1.1.1")
        second = get_or_create_target(db, SampleKind.ICMP, "1.1.1.1")

    assert first == second
    assert db.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 1


def test_same_address_different_kind_is_distinct(db: sqlite3.Connection) -> None:
    """1.1.1.1 pinged and 1.1.1.1 as a DNS resolver are different measurements."""
    with transaction(db):
        icmp = get_or_create_target(db, SampleKind.ICMP, "1.1.1.1")
        dns = get_or_create_target(db, SampleKind.DNS, "1.1.1.1")

    assert icmp != dns


def test_bulk_insert_reuses_target_ids(db: sqlite3.Connection) -> None:
    with transaction(db):
        insert_samples(
            db,
            "probe-a",
            [
                Sample(ts=NOW + i, kind=SampleKind.ICMP, target="1.1.1.1", success=True)
                for i in range(50)
            ],
            recv_ts=NOW,
        )

    assert db.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(DISTINCT target_id) FROM samples").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_duplicate_batch_is_rejected(db: sqlite3.Connection) -> None:
    """Duplicate delivery is the normal case: the agent retries across a flapping
    network and cannot know whether a timed-out request was applied."""
    with transaction(db):
        assert record_batch(db, "batch-1", "probe-a", NOW, 10) is True
    with transaction(db):
        assert record_batch(db, "batch-1", "probe-a", NOW + 1000, 10) is False

    assert db.execute("SELECT COUNT(*) FROM ingest_batches").fetchone()[0] == 1


def test_event_redetection_updates_in_place(db: sqlite3.Connection) -> None:
    """Detection re-runs over stored samples, so it must upsert rather than duplicate.

    The realistic trigger: an outage is first detected while still ongoing (no end
    time), then re-detected after backfill reveals when it ended.
    """
    ongoing = Event(
        event_type=EventType.OUTAGE,
        severity=Severity.CRITICAL,
        confidence=0.8,
        started_ts=NOW,
    )
    with transaction(db):
        insert_events(db, "probe-a", [ongoing])

    resolved = Event(
        event_type=EventType.OUTAGE,
        severity=Severity.CRITICAL,
        confidence=0.95,
        started_ts=NOW,
        ended_ts=NOW + 45_000,
        evidence={"samples_failed": 45},
    )
    with transaction(db):
        insert_events(db, "probe-a", [resolved])

    rows = db.execute("SELECT * FROM events").fetchall()
    assert len(rows) == 1, "re-detection duplicated the event"
    assert rows[0]["ended_ts"] == NOW + 45_000
    assert rows[0]["duration_ms"] == 45_000
    assert rows[0]["confidence"] == 0.95


def test_events_on_different_probes_coexist(db: sqlite3.Connection) -> None:
    """The uniqueness constraint is per-probe: a backbone outage hits every probe at
    the same instant, and each of those is a distinct event."""
    with transaction(db):
        upsert_probe(db, "probe-b", ProbeInfo(name="desktop"), NOW)
        event = Event(
            event_type=EventType.OUTAGE, severity=Severity.CRITICAL, confidence=0.9, started_ts=NOW
        )
        insert_events(db, "probe-a", [event])
        insert_events(db, "probe-b", [event])

    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2


# ---------------------------------------------------------------------------
# WiFi
# ---------------------------------------------------------------------------


def test_wifi_sample_stores_degraded_fields(db: sqlite3.Connection) -> None:
    """The macOS case: radio metrics present, BSSID structurally unavailable.

    Storing *why* a field is empty lets the dashboard show "unavailable on this
    platform" instead of implying data loss.
    """
    with transaction(db):
        insert_wifi_samples(
            db,
            "probe-a",
            [
                WifiSample(
                    ts=NOW,
                    ssid="TestNet-5G",
                    bssid=None,
                    rssi_dbm=-61,
                    noise_dbm=-88,
                    snr_db=27,
                    channel=149,
                    band="5GHz",
                    source="system_profiler",
                    degraded_fields=["bssid"],
                )
            ],
            recv_ts=NOW,
        )

    row = db.execute("SELECT * FROM wifi_samples").fetchone()
    assert row["bssid"] is None
    assert row["rssi_dbm"] == -61
    assert row["degraded_fields"] == '["bssid"]'


# ---------------------------------------------------------------------------
# Index usage
# ---------------------------------------------------------------------------


def _plan(conn: sqlite3.Connection, sql: str, params: tuple[object, ...] = ()) -> str:
    return " ".join(r["detail"] for r in conn.execute(f"EXPLAIN QUERY PLAN {sql}", params))


def test_probe_timerange_query_uses_index(db: sqlite3.Connection) -> None:
    """The dashboard's primary access pattern: one probe over a time window."""
    plan = _plan(
        db,
        "SELECT * FROM samples WHERE probe_id = ? AND ts BETWEEN ? AND ?",
        ("probe-a", NOW, NOW + 1000),
    )
    assert "ix_samples_probe_ts" in plan, plan
    assert "SCAN samples" not in plan, plan


def test_failure_query_uses_partial_index(db: sqlite3.Connection) -> None:
    """The partial failures index is the one that matters most.

    Nearly every diagnostic query is "show me the failures", and over a table that is
    ~99% successes this index stays tiny while keeping those queries instant. If the
    planner ignores it, outage investigation degrades to a full scan of millions of rows.
    """
    plan = _plan(
        db, "SELECT * FROM samples WHERE success = 0 AND ts BETWEEN ? AND ?", (NOW, NOW + 1000)
    )
    assert "ix_samples_failures" in plan, plan


def test_cross_probe_correlation_uses_index(db: sqlite3.Connection) -> None:
    """Correlation scans a time window across all probes to classify incident scope."""
    plan = _plan(db, "SELECT * FROM samples WHERE ts BETWEEN ? AND ?", (NOW, NOW + 1000))
    assert "ix_samples_ts" in plan, plan


def test_target_series_query_uses_index(db: sqlite3.Connection) -> None:
    """Per-target series, e.g. RTT to 1.1.1.1 over time."""
    plan = _plan(
        db,
        "SELECT * FROM samples WHERE kind = ? AND target_id = ? AND ts BETWEEN ? AND ?",
        (int(SampleKind.ICMP), 1, NOW, NOW + 1000),
    )
    assert "ix_samples_kind_target_ts" in plan, plan


def test_roam_detection_query_uses_bssid_index(db: sqlite3.Connection) -> None:
    plan = _plan(
        db, "SELECT * FROM wifi_samples WHERE bssid = ? ORDER BY ts", ("02:00:00:00:00:01",)
    )
    assert "ix_wifi_bssid_ts" in plan, plan


# ---------------------------------------------------------------------------
# Read-only access (the analysis-agent path)
# ---------------------------------------------------------------------------


def test_readonly_connection_can_read(tmp_path: Path) -> None:
    path = tmp_path / "ro.db"
    conn = init_db(path)
    with transaction(conn):
        upsert_probe(conn, "probe-a", ProbeInfo(name="pi"), NOW)
        insert_samples(
            conn,
            "probe-a",
            [Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True, value_ms=1.5)],
            recv_ts=NOW,
        )

    ro = connect_readonly(path)
    assert ro.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 1


def test_readonly_connection_cannot_write(tmp_path: Path) -> None:
    """Guards the analysis surface: an agent's SQL must never mutate monitoring data."""
    path = tmp_path / "ro2.db"
    init_db(path).close()
    ro = connect_readonly(path)

    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM samples")


def test_readonly_reads_concurrently_with_open_write(tmp_path: Path) -> None:
    """WAL's payoff: the dashboard keeps reading while ingest holds a write open."""
    path = tmp_path / "concurrent.db"
    writer = init_db(path)
    with transaction(writer):
        upsert_probe(writer, "probe-a", ProbeInfo(name="pi"), NOW)

    ro = connect_readonly(path)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "INSERT INTO samples (probe_id, ts, recv_ts, kind, target_id, success)"
        " SELECT 'probe-a', ?, ?, 1, target_id, 1 FROM targets LIMIT 1",
        (NOW, NOW),
    )
    try:
        # Sees the pre-transaction snapshot rather than blocking on the writer.
        assert ro.execute("SELECT COUNT(*) FROM probes").fetchone()[0] == 1
    finally:
        writer.execute("ROLLBACK")


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


def test_transaction_rolls_back_on_error(db: sqlite3.Connection) -> None:
    """A partially-applied batch would be worse than a rejected one."""
    with pytest.raises(RuntimeError), transaction(db):
        insert_samples(
            db,
            "probe-a",
            [Sample(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True)],
            recv_ts=NOW,
        )
        raise RuntimeError("simulated failure mid-batch")

    assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 0
