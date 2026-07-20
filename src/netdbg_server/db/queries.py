"""Typed query functions.

All SQL lives here rather than being scattered through API handlers, so the access
patterns stay visible next to the indexes in ``schema.sql`` that serve them.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from netdbg_common.enums import LinkType, ProbeStatus, SampleKind
from netdbg_common.models import Event, ProbeInfo, Sample, WifiSample

__all__ = [
    "StoredProbe",
    "get_or_create_target",
    "get_probe",
    "insert_events",
    "insert_samples",
    "insert_wifi_samples",
    "list_probes",
    "record_batch",
    "touch_probe_seen",
    "upsert_probe",
]


@dataclass(frozen=True, slots=True)
class StoredProbe:
    probe_id: str
    name: str
    display_name: str | None
    group_name: str | None
    location: str | None
    link_type: str
    status: str
    capabilities: list[str]
    clock_offset_ms: int
    first_seen_ts: int
    last_seen_ts: int | None

    @property
    def effective_name(self) -> str:
        """Admin-set display name when present, else the probe's self-reported name."""
        return self.display_name or self.name


def _row_to_probe(row: sqlite3.Row) -> StoredProbe:
    return StoredProbe(
        probe_id=row["probe_id"],
        name=row["name"],
        display_name=row["display_name"],
        group_name=row["group_name"],
        location=row["location"],
        link_type=row["link_type"],
        status=row["status"],
        capabilities=json.loads(row["capabilities"]),
        clock_offset_ms=row["clock_offset_ms"],
        first_seen_ts=row["first_seen_ts"],
        last_seen_ts=row["last_seen_ts"],
    )


def upsert_probe(
    conn: sqlite3.Connection,
    probe_id: str,
    info: ProbeInfo,
    now_ms: int,
    status: ProbeStatus = ProbeStatus.ACTIVE,
) -> None:
    """Register or re-register a probe.

    Re-registration (an agent restart) must not clobber admin-set fields, so
    ``display_name``, ``group_name``, ``location``, and ``status`` are deliberately
    absent from the UPDATE clause -- renaming a probe in the admin UI has to survive the
    agent restarting.
    """
    conn.execute(
        """
        INSERT INTO probes (
            probe_id, name, link_type, os_name, os_version, agent_version,
            capabilities, status, first_seen_ts, last_seen_ts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(probe_id) DO UPDATE SET
            name          = excluded.name,
            link_type     = excluded.link_type,
            os_name       = excluded.os_name,
            os_version    = excluded.os_version,
            agent_version = excluded.agent_version,
            capabilities  = excluded.capabilities,
            last_seen_ts  = excluded.last_seen_ts
        """,
        (
            probe_id,
            info.name,
            str(info.link_type),
            info.os_name,
            info.os_version,
            info.agent_version,
            json.dumps(info.capabilities),
            str(status),
            now_ms,
            now_ms,
        ),
    )


def get_probe(conn: sqlite3.Connection, probe_id: str) -> StoredProbe | None:
    row = conn.execute("SELECT * FROM probes WHERE probe_id = ?", (probe_id,)).fetchone()
    return _row_to_probe(row) if row is not None else None


def list_probes(conn: sqlite3.Connection, include_retired: bool = False) -> list[StoredProbe]:
    sql = "SELECT * FROM probes"
    params: tuple[str, ...] = ()
    if not include_retired:
        sql += " WHERE status != ?"
        params = (str(ProbeStatus.RETIRED),)
    sql += " ORDER BY COALESCE(group_name, ''), name"
    return [_row_to_probe(r) for r in conn.execute(sql, params)]


def touch_probe_seen(conn: sqlite3.Connection, probe_id: str, now_ms: int, offset_ms: int) -> None:
    """Update liveness and clock skew after a successful ingest.

    ``last_seen_ts`` uses server time, not the agent's: it answers "when did we last
    hear from this probe", which is what ``probe_silence`` detection needs. Using agent
    time would make a backfill of six-hour-old samples look like a fresh check-in.
    """
    conn.execute(
        "UPDATE probes SET last_seen_ts = ?, clock_offset_ms = ? WHERE probe_id = ?",
        (now_ms, offset_ms, probe_id),
    )


def get_or_create_target(
    conn: sqlite3.Connection, kind: SampleKind, address: str, label: str | None = None
) -> int:
    """Resolve a target address to its integer id, creating the row if needed."""
    row = conn.execute(
        "SELECT target_id FROM targets WHERE kind = ? AND address = ?", (int(kind), address)
    ).fetchone()
    if row is not None:
        return int(row["target_id"])

    cur = conn.execute(
        "INSERT INTO targets (kind, address, label) VALUES (?, ?, ?)",
        (int(kind), address, label),
    )
    return int(cur.lastrowid or 0)


def insert_samples(
    conn: sqlite3.Connection, probe_id: str, samples: list[Sample], recv_ts: int
) -> int:
    """Insert measurements. Returns the number of rows written.

    ``ts`` is written exactly as the agent stamped it -- never adjusted toward
    ``recv_ts`` and never replaced by server time. A backfilled sample must land at its
    measurement time, which is the whole reason the two columns exist separately.
    """
    if not samples:
        return 0

    target_ids: dict[tuple[int, str], int] = {}
    rows = []
    for s in samples:
        key = (int(s.kind), s.target)
        if key not in target_ids:
            target_ids[key] = get_or_create_target(conn, s.kind, s.target)
        rows.append(
            (
                probe_id,
                s.ts,
                recv_ts,
                int(s.kind),
                target_ids[key],
                1 if s.success else 0,
                s.value_ms,
                s.code,
                s.seq,
                s.interval_slip_ms,
                None if s.ntp_synced is None else (1 if s.ntp_synced else 0),
            )
        )

    conn.executemany(
        """
        INSERT INTO samples (
            probe_id, ts, recv_ts, kind, target_id, success,
            value_ms, code, seq, interval_slip_ms, ntp_synced
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return len(rows)


def insert_wifi_samples(
    conn: sqlite3.Connection, probe_id: str, samples: list[WifiSample], recv_ts: int
) -> int:
    if not samples:
        return 0

    conn.executemany(
        """
        INSERT INTO wifi_samples (
            probe_id, ts, recv_ts, ssid, bssid, rssi_dbm, noise_dbm, snr_db,
            channel, band, width_mhz, tx_rate_mbps, rx_rate_mbps, mcs, nss,
            tx_retries, tx_failed, beacon_loss, source, degraded_fields
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                probe_id,
                w.ts,
                recv_ts,
                w.ssid,
                w.bssid,
                w.rssi_dbm,
                w.noise_dbm,
                w.snr_db,
                w.channel,
                w.band,
                w.width_mhz,
                w.tx_rate_mbps,
                w.rx_rate_mbps,
                w.mcs,
                w.nss,
                w.tx_retries,
                w.tx_failed,
                w.beacon_loss,
                w.source,
                json.dumps(w.degraded_fields),
            )
            for w in samples
        ],
    )
    return len(samples)


def insert_events(
    conn: sqlite3.Connection, probe_id: str | None, events: list[Event], detector_ver: int = 1
) -> int:
    """Upsert events.

    Detection re-runs over stored samples -- both periodically and when backfilled data
    rewinds a probe's watermark -- so this must be idempotent. The
    ``(probe_id, event_type, started_ts)`` conflict target means a re-detected event
    updates in place rather than duplicating.
    """
    if not events:
        return 0

    conn.executemany(
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
        [
            (
                probe_id,
                str(e.event_type),
                e.subtype,
                str(e.severity),
                e.confidence,
                e.started_ts,
                e.ended_ts,
                None if e.ended_ts is None else e.ended_ts - e.started_ts,
                json.dumps(e.evidence),
                detector_ver,
            )
            for e in events
        ],
    )
    return len(events)


def record_batch(
    conn: sqlite3.Connection, batch_id: str, probe_id: str, recv_ts: int, sample_count: int
) -> bool:
    """Record an applied batch id. Returns False if it was already recorded.

    This is the idempotency guard. The agent retries across a flapping network and
    cannot tell whether a timed-out request was applied, so the same batch legitimately
    arrives more than once; a False here means "already applied, skip".
    """
    try:
        conn.execute(
            "INSERT INTO ingest_batches (batch_id, probe_id, recv_ts, sample_count)"
            " VALUES (?, ?, ?, ?)",
            (batch_id, probe_id, recv_ts, sample_count),
        )
    except sqlite3.IntegrityError:
        return False
    return True


def probe_link_type(info: ProbeInfo) -> LinkType:
    """Normalize a self-reported link type."""
    return info.link_type
