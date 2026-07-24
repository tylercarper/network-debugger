"""Detection engine: loads sample windows, runs rules, persists events.

Two properties define this engine, both flowing from the same fact -- the agent is on the
broken side of the network, so its view and its clock are suspect and detection must be
authoritative and server-side:

* **Idempotent and re-runnable over any window.** Running detection twice over the same
  range produces the same events, not duplicates, because events upsert on
  ``(probe_id, event_type, started_ts)``. This is what lets an improved rule be replayed
  over months of stored data to retroactively produce better events.

* **Backfill-aware.** Each probe has a watermark -- how far detection has processed. When
  a backfilled batch lands with samples *older* than the watermark, the watermark is
  rewound so the affected window is re-detected rather than skipped. Without this, the
  data that arrives late (which is exactly the data an outage produces) would never be
  analyzed.

Rules never see SQL. The engine builds an in-memory :class:`ProbeWindow` and hands it to
each rule, keeping rules pure and testable.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass

from netdbg_common.enums import SampleKind
from netdbg_server.db.engine import transaction
from netdbg_server.detect.rules.base import DetectedEvent, Rule
from netdbg_server.detect.rules.dns import DnsFailureRule
from netdbg_server.detect.rules.gateway_up_internet_down import GatewayUpInternetDownRule
from netdbg_server.detect.rules.latency import LatencySpikeRule
from netdbg_server.detect.rules.link import LinkChangeRule
from netdbg_server.detect.rules.loss import LossBurstRule
from netdbg_server.detect.rules.outage import OutageRule
from netdbg_server.detect.window import ProbeWindow, SampleRow

__all__ = ["DEFAULT_RULES", "DetectionEngine", "default_engine"]

log = logging.getLogger("netdbg.detect")

# Order is irrelevant to correctness -- events are keyed independently -- but grouping the
# related failure rules first reads more naturally in logs.
DEFAULT_RULES: list[Rule] = [
    OutageRule(),
    GatewayUpInternetDownRule(),
    LossBurstRule(),
    LatencySpikeRule(),
    DnsFailureRule(),
    LinkChangeRule(),
]

# When re-running a window, look back a little before the requested start so an event
# that began just before the window can still be detected with full context rather than
# clipped. Events upsert, so the overlap is harmless.
_LOOKBACK_MS = 60_000


@dataclass(frozen=True, slots=True)
class DetectionResult:
    probe_id: str
    events_written: int
    window_from: int
    window_to: int


class DetectionEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else DEFAULT_RULES

    # -- watermark ---------------------------------------------------------

    def watermark(self, conn: sqlite3.Connection, probe_id: str) -> int | None:
        row = conn.execute(
            "SELECT detected_through_ts FROM detect_watermarks WHERE probe_id = ?", (probe_id,)
        ).fetchone()
        return None if row is None else int(row["detected_through_ts"])

    def rewind_for_backfill(self, conn: sqlite3.Connection, probe_id: str, oldest_ts: int) -> None:
        """Move the watermark back to just before backfilled data.

        Called on ingest when a batch contains samples older than the current watermark.
        Rewinding means the next detection pass reprocesses the window the backfill landed
        in -- turning late-arriving outage data into detected events instead of a gap.
        """
        with transaction(conn):
            row = conn.execute(
                "SELECT detected_through_ts FROM detect_watermarks WHERE probe_id = ?",
                (probe_id,),
            ).fetchone()
            if row is not None and oldest_ts < row["detected_through_ts"]:
                conn.execute(
                    "UPDATE detect_watermarks SET detected_through_ts = ? WHERE probe_id = ?",
                    (oldest_ts - 1, probe_id),
                )

    # -- window loading ----------------------------------------------------

    def load_window(
        self, conn: sqlite3.Connection, probe_id: str, from_ts: int, to_ts: int
    ) -> ProbeWindow:
        """Build the in-memory window a rule operates on, from stored samples."""
        window = ProbeWindow(probe_id=probe_id, from_ts=from_ts, to_ts=to_ts)
        rows = conn.execute(
            """
            SELECT s.ts, s.success, s.value_ms, s.code, s.kind,
                   s.interval_slip_ms, s.ntp_synced, t.address AS target
            FROM samples s
            JOIN targets t ON t.target_id = s.target_id
            WHERE s.probe_id = ? AND s.ts >= ? AND s.ts <= ?
            ORDER BY s.ts
            """,
            (probe_id, from_ts, to_ts),
        )
        for r in rows:
            window.add(
                SampleRow(
                    ts=r["ts"],
                    success=bool(r["success"]),
                    value_ms=r["value_ms"],
                    code=r["code"],
                    interval_slip_ms=r["interval_slip_ms"],
                    ntp_synced=None if r["ntp_synced"] is None else bool(r["ntp_synced"]),
                ),
                SampleKind(r["kind"]),
                r["target"],
            )
        return window

    # -- running -----------------------------------------------------------

    def run_probe(
        self, conn: sqlite3.Connection, probe_id: str, from_ts: int, to_ts: int
    ) -> DetectionResult:
        """Detect over an explicit window for one probe and persist the events."""
        window = self.load_window(conn, probe_id, max(0, from_ts - _LOOKBACK_MS), to_ts)

        events: list[tuple[DetectedEvent, int]] = []
        for rule in self._rules:
            try:
                for ev in rule.detect(window):
                    events.append((ev, rule.detector_version))
            except Exception:
                # One broken rule must not sink the whole pass. Every other rule's events
                # for this probe should still be written.
                log.exception("rule %s failed on probe %s", rule.name, probe_id)

        written = self._persist(conn, probe_id, events)
        return DetectionResult(probe_id, written, window.from_ts, to_ts)

    def run_incremental(
        self, conn: sqlite3.Connection, probe_id: str, now_ms: int
    ) -> DetectionResult:
        """Detect from the probe's watermark up to ``now_ms``, then advance it.

        This is the periodic path. The watermark ensures each sample is processed once in
        the steady state, while :meth:`rewind_for_backfill` reopens windows when late data
        arrives.
        """
        wm = self.watermark(conn, probe_id)
        from_ts = 0 if wm is None else wm + 1
        result = self.run_probe(conn, probe_id, from_ts, now_ms)

        with transaction(conn):
            conn.execute(
                "INSERT INTO detect_watermarks (probe_id, detected_through_ts) VALUES (?, ?)"
                " ON CONFLICT(probe_id) DO UPDATE SET"
                " detected_through_ts = excluded.detected_through_ts",
                (probe_id, now_ms),
            )
        return result

    def run_all(self, conn: sqlite3.Connection, now_ms: int) -> list[DetectionResult]:
        """Run incremental detection for every active probe."""
        probe_ids = [
            r["probe_id"]
            for r in conn.execute("SELECT probe_id FROM probes WHERE status = 'active'")
        ]
        return [self.run_incremental(conn, pid, now_ms) for pid in probe_ids]

    # -- persistence -------------------------------------------------------

    def _persist(
        self, conn: sqlite3.Connection, probe_id: str, events: list[tuple[DetectedEvent, int]]
    ) -> int:
        if not events:
            return 0
        with transaction(conn):
            for ev, detector_ver in events:
                duration = None if ev.ended_ts is None else ev.ended_ts - ev.started_ts
                conn.execute(
                    """
                    INSERT INTO events (
                        probe_id, event_type, subtype, severity, confidence,
                        started_ts, ended_ts, duration_ms, evidence, detector_ver
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(probe_id, event_type, started_ts) DO UPDATE SET
                        subtype      = excluded.subtype,
                        severity     = excluded.severity,
                        confidence   = excluded.confidence,
                        ended_ts     = excluded.ended_ts,
                        duration_ms  = excluded.duration_ms,
                        evidence     = excluded.evidence,
                        detector_ver = excluded.detector_ver
                    """,
                    (
                        probe_id,
                        str(ev.event_type),
                        ev.subtype,
                        str(ev.severity),
                        ev.confidence,
                        ev.started_ts,
                        ev.ended_ts,
                        duration,
                        json.dumps(ev.evidence),
                        detector_ver,
                    ),
                )
        return len(events)


def default_engine() -> DetectionEngine:
    return DetectionEngine()
