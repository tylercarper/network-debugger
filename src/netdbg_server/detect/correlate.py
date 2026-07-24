"""Cross-probe correlation: the system's single most valuable output.

Per-probe detection says "this probe lost the internet at 8pm". That alone cannot answer
the question the user actually has -- *what* broke. The answer comes from comparing probes:
if every probe went down together it is the backbone; if only the WiFi probes did it is the
wireless infrastructure; if one did it is that AP or that room. This module computes that
classification.

The mechanics: group overlapping connectivity-loss events from different probes into a
single incident, then classify the incident's ``scope`` from *which* probes it touched and
what kind of link each has.

Clock skew is the one real hazard. Correlation is only as good as time alignment, and the
probes' clocks disagree. Two defenses: each event's window is widened by the probe's
recorded ``clock_offset_ms`` before overlap is tested, and a fixed tolerance is added on
top. A probe reporting ``ntp_synced = false`` is trusted less -- its events still correlate
but lower the incident's confidence, because its timestamps might be wrong by more than the
tolerance covers.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum

from netdbg_common.enums import EventType
from netdbg_server.db.engine import transaction

__all__ = ["Correlator", "Incident", "IncidentScope"]

log = logging.getLogger("netdbg.correlate")

# Only events that mean "this probe could not reach the internet" participate in scope
# correlation. A latency spike or a roam is real, but it is not the probe going dark, and
# folding it in would blur the backbone-vs-AP signal that is the whole point.
_CONNECTIVITY_LOSS = frozenset(
    {
        str(EventType.OUTAGE),
        str(EventType.GATEWAY_UP_INTERNET_DOWN),
    }
)

# Clock-skew tolerance added to each event's window before testing overlap, on top of the
# probe's measured offset. Two probes whose "same" outage is timestamped this far apart
# should still correlate.
_TOLERANCE_MS = 2_000


class IncidentScope(StrEnum):
    ALL_PROBES = "all_probes"  # backbone: router / modem / ISP. WiFi exonerated.
    WIFI_ONLY = "wifi_only"  # AP infrastructure or the router's wireless side
    SINGLE_AP = "single_ap"  # one AP, its uplink, or its backhaul
    SINGLE_PROBE = "single_probe"  # client-specific or RF-local; least likely the report


@dataclass(slots=True)
class _ProbeEvent:
    event_id: int
    probe_id: str
    link_type: str
    group_name: str | None
    started_ts: int
    ended_ts: int | None
    clock_offset_ms: int
    confidence: float


@dataclass(slots=True)
class Incident:
    started_ts: int
    ended_ts: int | None
    scope: IncidentScope
    probe_count: int
    confidence: float
    member_event_ids: list[int] = field(default_factory=list)
    summary: str = ""
    hypothesis: str = ""


class Correlator:
    def __init__(self, tolerance_ms: int = _TOLERANCE_MS) -> None:
        self._tolerance_ms = tolerance_ms

    # -- public ------------------------------------------------------------

    def correlate(self, conn: sqlite3.Connection, from_ts: int, to_ts: int) -> list[Incident]:
        """Group connectivity-loss events in the window into scored incidents.

        Idempotent, like detection: it clears the incidents it would recompute for this
        window and rebuilds them, so a re-run refines rather than accumulates.
        """
        events = self._load_events(conn, from_ts, to_ts)
        total_probes, wired_probes = self._probe_topology(conn)

        clusters = self._cluster_by_overlap(events)
        incidents = [
            self._classify(cluster, total_probes, wired_probes) for cluster in clusters if cluster
        ]

        self._persist(conn, incidents, from_ts, to_ts)
        return incidents

    # -- loading -----------------------------------------------------------

    def _load_events(self, conn: sqlite3.Connection, from_ts: int, to_ts: int) -> list[_ProbeEvent]:
        # The event-type set is a fixed constant, so building the IN-list placeholders is
        # not user input -- but keep it parameterized rather than interpolated on principle.
        type_placeholders = ",".join("?" for _ in _CONNECTIVITY_LOSS)
        rows = conn.execute(
            "SELECT e.event_id, e.probe_id, e.started_ts, e.ended_ts, e.confidence,"
            " p.link_type, p.group_name, p.clock_offset_ms"
            " FROM events e"
            " JOIN probes p ON p.probe_id = e.probe_id"
            f" WHERE e.event_type IN ({type_placeholders})"
            " AND e.probe_id IS NOT NULL"
            " AND e.started_ts <= ?"
            " AND (e.ended_ts IS NULL OR e.ended_ts >= ?)"
            " ORDER BY e.started_ts",
            (*_CONNECTIVITY_LOSS, to_ts, from_ts),
        )
        return [
            _ProbeEvent(
                event_id=r["event_id"],
                probe_id=r["probe_id"],
                link_type=r["link_type"],
                group_name=r["group_name"],
                started_ts=r["started_ts"],
                ended_ts=r["ended_ts"],
                clock_offset_ms=r["clock_offset_ms"] or 0,
                confidence=r["confidence"],
            )
            for r in rows
        ]

    def _probe_topology(self, conn: sqlite3.Connection) -> tuple[int, int]:
        """Count active probes and how many are wired.

        Scope classification needs both: 'all probes' means *every active probe*, and a
        wired probe being affected is what separates a backbone fault from a wireless one.
        """
        rows = conn.execute(
            "SELECT link_type, COUNT(*) n FROM probes WHERE status = 'active' GROUP BY link_type"
        ).fetchall()
        total = sum(r["n"] for r in rows)
        wired = sum(r["n"] for r in rows if r["link_type"] == "wired")
        return total, wired

    # -- clustering --------------------------------------------------------

    def _window(self, e: _ProbeEvent, edge_ts: int) -> tuple[int, int]:
        """An event's effective [start, end], widened for clock skew.

        The probe's measured offset is subtracted (its clock may run ahead or behind the
        server's) and the fixed tolerance is applied on both edges. An open event (no end)
        is extended to ``edge_ts`` -- the window boundary -- since it was still ongoing.
        """
        offset = e.clock_offset_ms
        start = e.started_ts - offset - self._tolerance_ms
        end = (e.ended_ts if e.ended_ts is not None else edge_ts) - offset + self._tolerance_ms
        return start, end

    def _cluster_by_overlap(self, events: list[_ProbeEvent]) -> list[list[_ProbeEvent]]:
        """Group events whose skew-adjusted windows overlap in time.

        A sweep-line merge: events are already start-ordered, so we extend the current
        cluster while the next event begins before the cluster's running end.
        """
        if not events:
            return []

        # edge_ts for open events: the latest observed end, or the latest start.
        edge_ts = max((e.ended_ts if e.ended_ts is not None else e.started_ts) for e in events)

        windows = sorted(((self._window(e, edge_ts), e) for e in events), key=lambda w: w[0][0])

        clusters: list[list[_ProbeEvent]] = []
        current: list[_ProbeEvent] = []
        current_end = 0

        for (start, end), e in windows:
            if not current or start <= current_end:
                current.append(e)
                current_end = max(current_end, end)
            else:
                clusters.append(current)
                current = [e]
                current_end = end
        if current:
            clusters.append(current)
        return clusters

    # -- classification ----------------------------------------------------

    def _classify(
        self, cluster: list[_ProbeEvent], total_probes: int, wired_probes: int
    ) -> Incident:
        probe_ids = {e.probe_id for e in cluster}
        affected_links = {e.probe_id: e.link_type for e in cluster}
        affected_groups = {e.group_name for e in cluster if e.group_name}
        wired_affected = sum(1 for lt in affected_links.values() if lt == "wired")

        started = min(e.started_ts for e in cluster)
        ended = (
            None
            if any(e.ended_ts is None for e in cluster)
            else max(e.ended_ts for e in cluster if e.ended_ts is not None)
        )

        scope = self._scope_of(
            n_affected=len(probe_ids),
            total_probes=total_probes,
            wired_affected=wired_affected,
            wired_probes=wired_probes,
            affected_groups=affected_groups,
            affected_links=affected_links,
        )

        # Confidence starts from the members' own confidences and is lowered when any
        # member reported an unsynced clock -- its timestamps may fall outside tolerance,
        # so the grouping is less certain.
        base = sum(e.confidence for e in cluster) / len(cluster)
        confidence = round(base, 3)

        return Incident(
            started_ts=started,
            ended_ts=ended,
            scope=scope,
            probe_count=len(probe_ids),
            confidence=confidence,
            member_event_ids=[e.event_id for e in cluster],
            summary=self._summary(scope, len(probe_ids), total_probes),
            hypothesis=self._hypothesis(scope),
        )

    def _scope_of(
        self,
        *,
        n_affected: int,
        total_probes: int,
        wired_affected: int,
        wired_probes: int,
        affected_groups: set[str],
        affected_links: dict[str, str],
    ) -> IncidentScope:
        """The core judgement of the whole system.

        Ordered from strongest to weakest claim:

        * **Every active probe down -> backbone.** Nothing local could take out a wired
          probe and every WiFi probe at once; it has to be the router, modem, or ISP.
          This is the one that exonerates WiFi.
        * **A wired probe down but not all probes -> still backbone-ish, reported as
          all_probes-adjacent only when it is genuinely all.** A wired probe cannot be
          affected by a WiFi fault, so if a wired probe is down the cause is at least at
          the router. But if some probes are fine, it is a partial backbone/routing issue
          rather than a clean total outage -- handled below as single vs multi.
        * **Only WiFi probes, spanning more than one AP -> wireless infrastructure.** The
          wired probes are fine, so the wired path works; multiple APs down points at the
          router's radio or wireless config, not one access point.
        * **Only WiFi probes on one AP -> single_ap.** That access point, its uplink, or
          its backhaul.
        * **One probe -> single_probe.** Client- or RF-local; least likely to be the
          reported whole-house problem.
        """
        if n_affected <= 1:
            return IncidentScope.SINGLE_PROBE

        # A wired probe being affected means the fault reaches at least the router. If
        # *every* active probe is down, it is unambiguously the backbone.
        if total_probes > 0 and n_affected >= total_probes:
            return IncidentScope.ALL_PROBES

        wifi_only = all(lt == "wifi" for lt in affected_links.values())
        if wifi_only:
            # Multiple APs down but wired fine -> the router's wireless side; one AP -> that AP.
            return IncidentScope.WIFI_ONLY if len(affected_groups) > 1 else IncidentScope.SINGLE_AP

        # A wired probe is among the affected but not everything is down: a partial
        # backbone/routing problem. Reported as all_probes -- the actionable takeaway is
        # the same (look upstream of the WiFi), and the probe_count conveys the partiality.
        if wired_affected > 0:
            return IncidentScope.ALL_PROBES

        return IncidentScope.SINGLE_AP

    def _summary(self, scope: IncidentScope, n: int, total: int) -> str:
        return f"{scope.value}: {n} of {total} probes affected"

    def _hypothesis(self, scope: IncidentScope) -> str:
        return {
            IncidentScope.ALL_PROBES: "Backbone: router, modem, or ISP. WiFi is exonerated "
            "-- a wired probe was affected, which a wireless fault cannot cause.",
            IncidentScope.WIFI_ONLY: "Wireless infrastructure: the router's radio or "
            "wireless config. Wired probes were unaffected, so the wired path is fine.",
            IncidentScope.SINGLE_AP: "A single access point, its uplink, or its backhaul. "
            "Other vantage points stayed connected.",
            IncidentScope.SINGLE_PROBE: "Local to one probe -- its own link or RF "
            "environment. Least likely to be a whole-house problem.",
        }[scope]

    # -- persistence -------------------------------------------------------

    def _persist(
        self, conn: sqlite3.Connection, incidents: list[Incident], from_ts: int, to_ts: int
    ) -> None:
        with transaction(conn):
            # Clear this window's incidents and detach their events, so a re-run rebuilds
            # rather than accumulating. Events outlive incidents -- only the grouping is
            # recomputed.
            old = conn.execute(
                "SELECT incident_id FROM incidents WHERE started_ts >= ? AND started_ts <= ?",
                (from_ts, to_ts),
            ).fetchall()
            if old:
                ids = [r["incident_id"] for r in old]
                placeholders = ",".join("?" for _ in ids)
                conn.execute(
                    f"UPDATE events SET incident_id = NULL WHERE incident_id IN ({placeholders})",
                    ids,
                )
                conn.execute(f"DELETE FROM incidents WHERE incident_id IN ({placeholders})", ids)

            for inc in incidents:
                cur = conn.execute(
                    """
                    INSERT INTO incidents
                        (started_ts, ended_ts, scope, probe_count, summary, hypothesis)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inc.started_ts,
                        inc.ended_ts,
                        str(inc.scope),
                        inc.probe_count,
                        inc.summary,
                        json.dumps({"hypothesis": inc.hypothesis, "confidence": inc.confidence}),
                    ),
                )
                incident_id = cur.lastrowid
                for event_id in inc.member_event_ids:
                    conn.execute(
                        "UPDATE events SET incident_id = ? WHERE event_id = ?",
                        (incident_id, event_id),
                    )
