"""Spool durability tests.

The scenarios here are the ones that only happen when things are already going wrong:
a probe crashing mid-outage, a multi-hour partition, a disk filling up. That is the whole
point of the spool -- it exists for the moments when the server cannot be reached, so the
tests are written around failure rather than around the happy path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netdbg_agent.spool import Spool
from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_common.models import Event, Sample, WifiSample

NOW = 1_700_000_000_000


@pytest.fixture
def spool(tmp_path: Path) -> Spool:
    return Spool(tmp_path / "spool.db")


def _samples(n: int, start: int = NOW, ok: bool = True) -> list[Sample]:
    return [
        Sample(
            ts=start + i * 1000,
            kind=SampleKind.ICMP,
            target="1.1.1.1",
            success=ok,
            value_ms=12.5 if ok else None,
        )
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Durability
# ---------------------------------------------------------------------------


def test_samples_survive_process_restart(tmp_path: Path) -> None:
    """The core promise: data written before a crash is still there afterwards.

    Simulated by closing the connection without any graceful flush, then reopening --
    which is what a killed process or a power cut leaves behind.
    """
    path = tmp_path / "crash.db"
    s1 = Spool(path)
    s1.add_samples(_samples(50))
    s1.close()  # no flush, no cleanup -- as if the process died here

    s2 = Spool(path)
    assert s2.pending_count() == 50


def test_synchronous_full_is_set(spool: Spool) -> None:
    """FULL, not NORMAL.

    The spool is the single copy of this probe's measurements. NORMAL risks losing the
    last transactions on power loss -- which on a probe means losing the seconds
    immediately before a power event, often the most interesting ones.
    """
    value = spool._conn.execute("PRAGMA synchronous").fetchone()[0]
    assert value == 2, "synchronous should be FULL (2)"


def test_claimed_rows_are_reclaimed_after_crash(tmp_path: Path) -> None:
    """A crash mid-flight must not orphan data.

    When a batch is claimed but the process dies before confirmation, whether the server
    applied it is unknowable from here. The rows are re-sent, and the server's batch_id
    idempotency absorbs the duplicate. Re-sending is recoverable; dropping is not.
    """
    path = tmp_path / "orphan.db"
    s1 = Spool(path)
    s1.add_samples(_samples(10))
    s1.claim_batch("batch-in-flight", limit=10)
    assert s1.unclaimed_count() == 0
    s1.close()  # died mid-flight

    s2 = Spool(path)
    assert s2.pending_count() == 10, "claimed rows must not be lost"
    assert s2.unclaimed_count() == 10, "orphaned claim must be released for retry"


def test_partial_write_is_rolled_back(tmp_path: Path) -> None:
    """A half-written batch would leave an invisible gap in the timeline."""
    path = tmp_path / "partial.db"
    spool = Spool(path)
    spool.add_samples(_samples(5))

    class Exploding(Sample):
        def model_dump_json(self, **kw: object) -> str:
            raise RuntimeError("serialization blew up")

    with pytest.raises(RuntimeError):
        spool.add_samples(
            [
                *_samples(2, start=NOW + 100_000),
                Exploding(ts=NOW, kind=SampleKind.ICMP, target="gw", success=True),
            ]
        )

    assert spool.pending_count() == 5, "failed write left partial data behind"


# ---------------------------------------------------------------------------
# Timestamp preservation -- the invariant the system depends on
# ---------------------------------------------------------------------------


def test_timestamps_survive_spooling_byte_for_byte(spool: Spool) -> None:
    """A sample buffered for hours must ship with its original measurement time.

    If the spool nudged timestamps, a backfilled outage would land at the moment
    connectivity *returned* rather than when it broke -- precisely inverted from what is
    needed to diagnose it.
    """
    original = _samples(20, start=NOW - 6 * 3_600_000, ok=False)
    spool.add_samples(original)

    claimed = spool.claim_batch("b1", limit=100)

    assert [s.ts for s in claimed.samples] == [s.ts for s in original]
    assert claimed.samples == original, "round trip altered the samples"


def test_payloads_are_stored_verbatim(spool: Spool) -> None:
    """Stronger than model equality: the stored JSON matches what was serialized."""
    original = _samples(3)
    spool.add_samples(original)

    assert spool._raw_payloads() == [s.model_dump_json() for s in original]


def test_mixed_kinds_roundtrip(spool: Spool) -> None:
    """A real batch carries measurements, radio telemetry, and agent-side events."""
    spool.add_samples(_samples(3))
    spool.add_wifi_samples(
        [
            WifiSample(
                ts=NOW,
                ssid="TestNet-5G",
                bssid="02:00:00:00:00:01",
                rssi_dbm=-58,
                source="iw",
            )
        ]
    )
    spool.add_events(
        [
            Event(
                event_type=EventType.CLOCK_STEP,
                severity=Severity.INFO,
                confidence=1.0,
                started_ts=NOW,
                evidence={"delta_ms": 3_600_000},
            )
        ]
    )

    batch = spool.claim_batch("b1", limit=100)

    assert len(batch.samples) == 3
    assert len(batch.wifi_samples) == 1
    assert len(batch.events) == 1
    assert len(batch) == 5


# ---------------------------------------------------------------------------
# Claim / confirm / release
# ---------------------------------------------------------------------------


def test_confirm_deletes_only_after_delivery(spool: Spool) -> None:
    spool.add_samples(_samples(10))
    spool.claim_batch("b1", limit=4)

    assert spool.pending_count() == 10, "claiming must not delete"

    assert spool.confirm_batch("b1") == 4
    assert spool.pending_count() == 6


def test_release_returns_batch_for_retry(spool: Spool) -> None:
    """A failed send must leave the data queued, never dropped."""
    spool.add_samples(_samples(10))
    spool.claim_batch("b1", limit=4)

    assert spool.release_batch("b1") == 4
    assert spool.unclaimed_count() == 10


def test_claim_does_not_reissue_claimed_rows(spool: Spool) -> None:
    """Two in-flight batches must not overlap, or rows would ship twice."""
    spool.add_samples(_samples(10))

    first = spool.claim_batch("b1", limit=4)
    second = spool.claim_batch("b2", limit=4)

    assert len(first.samples) == 4
    assert len(second.samples) == 4
    assert {s.ts for s in first.samples}.isdisjoint({s.ts for s in second.samples})


def test_claim_returns_oldest_first(spool: Spool) -> None:
    """Backfill should replay in measurement order.

    Shipping newest-first would make the server's detection watermark jump around
    instead of advancing steadily through the recovered window.
    """
    spool.add_samples(_samples(10, start=NOW))
    batch = spool.claim_batch("b1", limit=3)

    assert [s.ts for s in batch.samples] == [NOW, NOW + 1000, NOW + 2000]


def test_claim_on_empty_spool_is_harmless(spool: Spool) -> None:
    batch = spool.claim_batch("b1", limit=100)
    assert batch.is_empty
    assert len(batch) == 0


# ---------------------------------------------------------------------------
# The multi-hour partition
# ---------------------------------------------------------------------------


def test_multi_hour_partition_loses_nothing(spool: Spool) -> None:
    """The defining scenario for this component.

    Six hours of measurement at 1/s with no server reachable, then recovery. Every
    sample must survive, in order, with its original timestamp -- this is the data that
    explains the outage, and it is the data most at risk.
    """
    outage_start = NOW
    per_hour = 3600
    total = 6 * per_hour

    # Measurement continues throughout the partition; each hour is a separate write, as
    # the collector would do it.
    for hour in range(6):
        spool.add_samples(_samples(per_hour, start=outage_start + hour * 3_600_000, ok=False))

    assert spool.pending_count() == total

    # Connectivity returns; the shipper drains in batches.
    drained: list[Sample] = []
    batch_num = 0
    while spool.unclaimed_count() > 0:
        batch_id = f"recovery-{batch_num}"
        batch = spool.claim_batch(batch_id, limit=1000)
        drained.extend(batch.samples)
        spool.confirm_batch(batch_id)
        batch_num += 1

    assert len(drained) == total, "samples lost across the partition"
    assert spool.pending_count() == 0

    timestamps = [s.ts for s in drained]
    assert timestamps == sorted(timestamps), "backfill arrived out of order"
    assert timestamps[0] == outage_start, "oldest sample's timestamp was altered"
    assert timestamps[-1] == outage_start + (total - 1) * 1000


def test_partition_with_intermittent_failures_loses_nothing(spool: Spool) -> None:
    """Recovery is rarely clean -- the link often flaps before it settles.

    Alternating success and failure must still converge with nothing lost.
    """
    spool.add_samples(_samples(500))

    delivered = 0
    attempt = 0
    while spool.unclaimed_count() > 0 and attempt < 100:
        batch_id = f"flappy-{attempt}"
        batch = spool.claim_batch(batch_id, limit=50)
        if attempt % 2 == 0:
            spool.release_batch(batch_id)  # send failed
        else:
            delivered += len(batch.samples)
            spool.confirm_batch(batch_id)
        attempt += 1

    assert delivered == 500
    assert spool.pending_count() == 0


# ---------------------------------------------------------------------------
# Bounded growth
# ---------------------------------------------------------------------------


def test_trim_drops_oldest_when_over_cap(tmp_path: Path) -> None:
    """If a probe is disconnected long enough to hit the cap, recent data describes the
    current state of the problem while the oldest describes a period long past."""
    spool = Spool(tmp_path / "trim.db", max_rows=100)
    spool.add_samples(_samples(150, start=NOW))

    dropped = spool.trim()

    assert dropped == 50
    assert spool.pending_count() == 100
    assert spool.oldest_ts() == NOW + 50 * 1000, "trim should drop the oldest, not the newest"


def test_trim_is_a_noop_under_cap(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "under.db", max_rows=1000)
    spool.add_samples(_samples(10))

    assert spool.trim() == 0
    assert spool.pending_count() == 10


def test_trim_prefers_dropping_unclaimed_rows(tmp_path: Path) -> None:
    """A batch mid-flight must not be deleted out from under the shipper."""
    spool = Spool(tmp_path / "inflight.db", max_rows=10)
    spool.add_samples(_samples(20))
    spool.claim_batch("in-flight", limit=5)

    spool.trim()

    remaining = spool._conn.execute(
        "SELECT COUNT(*) FROM spool WHERE batch_id = 'in-flight'"
    ).fetchone()[0]
    assert remaining == 5, "in-flight batch was trimmed away"


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_identity_persists_across_restart(tmp_path: Path) -> None:
    """A restart must resume as the same probe, not fragment its own history."""
    path = tmp_path / "identity.db"
    s1 = Spool(path)
    s1.set_identity("probe_id", "abc-123")
    s1.set_identity("token", "secret")
    s1.close()

    s2 = Spool(path)
    assert s2.get_identity("probe_id") == "abc-123"
    assert s2.get_identity("token") == "secret"


def test_identity_overwrite(spool: Spool) -> None:
    """Re-registration rotates the token; the new value must win."""
    spool.set_identity("token", "old")
    spool.set_identity("token", "new")
    assert spool.get_identity("token") == "new"


def test_missing_identity_is_none(spool: Spool) -> None:
    assert spool.get_identity("probe_id") is None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_report_backlog(spool: Spool) -> None:
    """Backlog age is a direct read on how long the server has been unreachable."""
    spool.add_samples(_samples(10, start=NOW))
    stats = spool.stats()

    assert stats["pending"] == 10
    assert stats["unclaimed"] == 10
    assert stats["oldest_ts"] == NOW
