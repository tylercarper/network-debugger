"""Durable local spool.

This is the reliability foundation of the whole system. The server sits behind the
network being debugged, so it is unreachable *exactly* when the data matters most. Every
measurement is therefore written to local durable storage before any network attempt is
made, and only removed once the server has confirmed receipt.

Three properties are non-negotiable:

1. **Durable, not in-memory.** A probe that crashes or loses power mid-outage would
   otherwise lose precisely the data that outage produced. SQLite with
   ``synchronous=FULL`` -- unlike the server, this database is small and written at a
   modest rate, so the fsync cost is affordable and losing the tail is not.

2. **Write before ship.** A sample exists on disk before anything touches the network.
   There is no window where a measurement lives only in memory.

3. **Timestamps are never rewritten.** A sample buffered for six hours ships with its
   original measurement time. This is what makes a backfilled outage land at the moment
   it *broke* rather than the moment connectivity returned.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from netdbg_common.models import Event, Sample, WifiSample

__all__ = ["PendingBatch", "Spool"]

_SCHEMA = """
PRAGMA journal_mode = WAL;

-- FULL, not NORMAL. The server can afford NORMAL because it is fed by many probes and
-- writes constantly; a probe's spool is the single copy of its own measurements, and a
-- power cut during an outage is exactly the scenario where the last few seconds matter.
PRAGMA synchronous = FULL;

PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS spool (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    kind    TEXT NOT NULL,          -- 'sample' | 'wifi' | 'event'
    ts      INTEGER NOT NULL,       -- measurement time, for ordering and diagnostics
    payload TEXT NOT NULL,          -- the model as JSON, shipped verbatim

    -- Set when a batch is claimed for shipping, cleared if that ship fails. Rows are
    -- deleted only on confirmed delivery, so a crash mid-flight loses nothing: the
    -- claim is forgotten on restart and the rows are simply re-sent. The server's
    -- batch_id idempotency absorbs the resulting duplicate.
    batch_id TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS ix_spool_unclaimed ON spool(id) WHERE batch_id IS NULL;
CREATE INDEX IF NOT EXISTS ix_spool_batch ON spool(batch_id);

-- Persisted identity, so a restart re-registers as the same probe rather than
-- appearing as a new one and fragmenting its own history.
CREATE TABLE IF NOT EXISTS identity (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""


@dataclass(frozen=True, slots=True)
class PendingBatch:
    """A claimed set of spool rows, ready to ship."""

    batch_id: str
    samples: list[Sample]
    wifi_samples: list[WifiSample]
    events: list[Event]

    def __len__(self) -> int:
        return len(self.samples) + len(self.wifi_samples) + len(self.events)

    @property
    def is_empty(self) -> bool:
        return len(self) == 0


class Spool:
    """Durable local buffer for measurements awaiting delivery."""

    def __init__(self, db_path: str | Path, max_rows: int = 2_000_000) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._max_rows = max_rows
        self._reclaim_orphans()

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def _reclaim_orphans(self) -> None:
        """Release claims left behind by a crash.

        A batch claimed but never confirmed means the process died mid-flight. Whether
        the server actually applied it is unknowable from here -- so the rows are
        re-sent, and the server's ``batch_id`` idempotency makes a repeat harmless.
        Re-sending a duplicate is recoverable; dropping data is not.
        """
        self._conn.execute("UPDATE spool SET batch_id = NULL WHERE batch_id IS NOT NULL")

    # -- identity ----------------------------------------------------------

    def get_identity(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM identity WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def set_identity(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO identity (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # -- writing -----------------------------------------------------------

    def add_samples(self, samples: Sequence[Sample]) -> int:
        return self._add("sample", [(s.ts, s.model_dump_json()) for s in samples])

    def add_wifi_samples(self, samples: Sequence[WifiSample]) -> int:
        return self._add("wifi", [(w.ts, w.model_dump_json()) for w in samples])

    def add_events(self, events: Sequence[Event]) -> int:
        return self._add("event", [(e.started_ts, e.model_dump_json()) for e in events])

    def _add(self, kind: str, rows: list[tuple[int, str]]) -> int:
        """Persist rows in a single committed transaction.

        Either the whole write lands or none of it does -- a partially written batch of
        measurements would be worse than none, since the gap would be invisible.
        """
        if not rows:
            return 0
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.executemany(
                "INSERT INTO spool (kind, ts, payload) VALUES (?, ?, ?)",
                [(kind, ts, payload) for ts, payload in rows],
            )
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")
        return len(rows)

    # -- shipping ----------------------------------------------------------

    def claim_batch(self, batch_id: str, limit: int) -> PendingBatch:
        """Claim the oldest unshipped rows for delivery.

        Oldest-first so that after an outage the backfill replays in measurement order,
        which keeps the server's detection watermark moving forward sensibly instead of
        jumping around.

        Claiming is a marker, not a removal: rows survive until delivery is confirmed.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self._conn.execute(
                "SELECT id, kind, payload FROM spool WHERE batch_id IS NULL ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()

            if rows:
                self._conn.executemany(
                    "UPDATE spool SET batch_id = ? WHERE id = ?",
                    [(batch_id, r["id"]) for r in rows],
                )
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

        samples: list[Sample] = []
        wifi: list[WifiSample] = []
        events: list[Event] = []
        for r in rows:
            payload = r["payload"]
            if r["kind"] == "sample":
                samples.append(Sample.model_validate_json(payload))
            elif r["kind"] == "wifi":
                wifi.append(WifiSample.model_validate_json(payload))
            else:
                events.append(Event.model_validate_json(payload))

        return PendingBatch(batch_id=batch_id, samples=samples, wifi_samples=wifi, events=events)

    def confirm_batch(self, batch_id: str) -> int:
        """Delete a delivered batch. Called only after the server confirms receipt."""
        cur = self._conn.execute("DELETE FROM spool WHERE batch_id = ?", (batch_id,))
        return cur.rowcount

    def release_batch(self, batch_id: str) -> int:
        """Return a failed batch to the queue for retry."""
        cur = self._conn.execute("UPDATE spool SET batch_id = NULL WHERE batch_id = ?", (batch_id,))
        return cur.rowcount

    # -- bounds ------------------------------------------------------------

    def trim(self) -> int:
        """Drop the oldest rows if the spool exceeds its cap.

        Oldest-first is the right sacrifice: if a probe has been disconnected long
        enough to hit this cap, recent measurements describe the current state of the
        problem while the oldest describe a period already long past.

        Unclaimed rows are dropped in preference to claimed ones, so a batch mid-flight
        is not deleted out from under the shipper.
        """
        total = self.pending_count()
        excess = total - self._max_rows
        if excess <= 0:
            return 0

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "DELETE FROM spool WHERE id IN ("
                "  SELECT id FROM spool ORDER BY (batch_id IS NOT NULL), id LIMIT ?"
                ")",
                (excess,),
            )
            dropped = cur.rowcount
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")
        return dropped

    # -- introspection -----------------------------------------------------

    def pending_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM spool").fetchone()[0])

    def unclaimed_count(self) -> int:
        return int(
            self._conn.execute("SELECT COUNT(*) FROM spool WHERE batch_id IS NULL").fetchone()[0]
        )

    def oldest_ts(self) -> int | None:
        row = self._conn.execute("SELECT MIN(ts) AS t FROM spool").fetchone()
        return None if row["t"] is None else int(row["t"])

    def stats(self) -> dict[str, object]:
        """Spool health, surfaced for diagnostics.

        ``backlog_ms`` is the age of the oldest buffered measurement -- a direct read on
        how long this probe has been unable to reach the server.
        """
        oldest = self.oldest_ts()
        return {
            "pending": self.pending_count(),
            "unclaimed": self.unclaimed_count(),
            "oldest_ts": oldest,
            "max_rows": self._max_rows,
        }

    def _raw_payloads(self) -> list[str]:
        """Test hook: every payload as stored, to assert byte-level preservation."""
        rows = self._conn.execute("SELECT payload FROM spool ORDER BY id")
        return [str(r["payload"]) for r in rows]
