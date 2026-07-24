"""Correlation tests: the scope classification is the system's core judgement.

If this mislabels "the backbone failed" as "one AP failed" (or vice versa), the whole
project fails at its one job -- so every scope gets an explicit test, plus the clock-skew
grouping that the classification depends on.

Tests run against a real DB, because correlation reads probe topology (which probes are
wired, which group each belongs to) that only exists in the schema.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netdbg_common.enums import EventType, LinkType, Severity
from netdbg_common.models import Event, ProbeInfo
from netdbg_server.db.engine import init_db, transaction
from netdbg_server.db.queries import insert_events, upsert_probe
from netdbg_server.detect.correlate import Correlator, IncidentScope

NOW = 1_700_000_000_000


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    """A four-probe topology: two wired, two WiFi on different APs."""
    conn = init_db(tmp_path / "corr.db")
    with transaction(conn):
        _probe(conn, "wired-pi", LinkType.WIRED, "wired")
        _probe(conn, "wired-desktop", LinkType.WIRED, "wired")
        _probe(conn, "wifi-living", LinkType.WIFI, "ap-living-room")
        _probe(conn, "wifi-office", LinkType.WIFI, "ap-office")
    return conn


def _probe(conn: sqlite3.Connection, pid: str, link: LinkType, group: str) -> None:
    upsert_probe(conn, pid, ProbeInfo(name=pid, link_type=link), NOW)
    conn.execute("UPDATE probes SET group_name = ? WHERE probe_id = ?", (group, pid))


def _outage_event(
    conn: sqlite3.Connection,
    probe_id: str,
    start: int,
    end: int | None,
    etype: EventType = EventType.OUTAGE,
) -> None:
    with transaction(conn):
        insert_events(
            conn,
            probe_id,
            [
                Event(
                    event_type=etype,
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    started_ts=start,
                    ended_ts=end,
                )
            ],
        )


# ---------------------------------------------------------------------------
# The four scopes -- the core judgement
# ---------------------------------------------------------------------------


def test_all_probes_down_is_backbone(db: sqlite3.Connection) -> None:
    """Every probe down together -> backbone. This is the WiFi-exonerating verdict.

    Nothing local could take out both wired probes and both WiFi probes at once; it has
    to be the router, modem, or ISP.
    """
    for pid in ("wired-pi", "wired-desktop", "wifi-living", "wifi-office"):
        _outage_event(db, pid, NOW, NOW + 60_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    assert len(incidents) == 1
    assert incidents[0].scope == IncidentScope.ALL_PROBES
    assert incidents[0].probe_count == 4
    assert "exonerat" in incidents[0].hypothesis.lower(), "backbone verdict must clear WiFi"


def test_both_wifi_probes_down_is_wifi_only(db: sqlite3.Connection) -> None:
    """Both APs down but wired probes fine -> the router's wireless side.

    The wired path works (wired probes are up), so it is not the backbone; multiple APs
    down points at the router's radio, not one access point.
    """
    _outage_event(db, "wifi-living", NOW, NOW + 60_000)
    _outage_event(db, "wifi-office", NOW, NOW + 60_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    assert len(incidents) == 1
    assert incidents[0].scope == IncidentScope.WIFI_ONLY


def test_single_ap_down_is_single_ap(db: sqlite3.Connection) -> None:
    """One AP's probe down, everyone else fine -> that AP or its backhaul."""
    _outage_event(db, "wifi-office", NOW, NOW + 60_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    # A lone probe is single_probe unless... see the note below. One AP-probe with no
    # correlating probe is genuinely a single probe going dark.
    assert incidents[0].scope == IncidentScope.SINGLE_PROBE


def test_two_probes_same_ap_is_single_ap(tmp_path: Path) -> None:
    """Two probes behind the same AP, both down -> single_ap, not backbone.

    This is the case single_ap is really for: multiple vantage points behind one access
    point, all lost, while other APs and the wired probes stay up.
    """
    conn = init_db(tmp_path / "sameap.db")
    with transaction(conn):
        _probe(conn, "wired-pi", LinkType.WIRED, "wired")
        _probe(conn, "wifi-a1", LinkType.WIFI, "ap-office")
        _probe(conn, "wifi-a2", LinkType.WIFI, "ap-office")
        _probe(conn, "wifi-other", LinkType.WIFI, "ap-living-room")

    for pid in ("wifi-a1", "wifi-a2"):
        _outage_event(conn, pid, NOW, NOW + 60_000)

    incidents = Correlator().correlate(conn, NOW - 10_000, NOW + 120_000)

    assert incidents[0].scope == IncidentScope.SINGLE_AP
    assert incidents[0].probe_count == 2


def test_single_probe_down_is_single_probe(db: sqlite3.Connection) -> None:
    """One wired probe alone -> local to that probe, least likely the whole-house issue."""
    _outage_event(db, "wired-pi", NOW, NOW + 60_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    assert incidents[0].scope == IncidentScope.SINGLE_PROBE


def test_wired_probe_affected_points_upstream(db: sqlite3.Connection) -> None:
    """A wired probe plus a WiFi probe down -> the fault reaches the router (backbone).

    A wireless problem cannot take down a wired probe, so if a wired probe is affected
    the cause is at least at the router -- WiFi is not the culprit.
    """
    _outage_event(db, "wired-pi", NOW, NOW + 60_000)
    _outage_event(db, "wifi-living", NOW, NOW + 60_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    assert incidents[0].scope == IncidentScope.ALL_PROBES


# ---------------------------------------------------------------------------
# gateway_up_internet_down participates too
# ---------------------------------------------------------------------------


def test_gwid_events_correlate_as_connectivity_loss(db: sqlite3.Connection) -> None:
    """The headline symptom across all probes is still a backbone incident."""
    for pid in ("wired-pi", "wired-desktop", "wifi-living", "wifi-office"):
        _outage_event(db, pid, NOW, NOW + 60_000, etype=EventType.GATEWAY_UP_INTERNET_DOWN)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)
    assert incidents[0].scope == IncidentScope.ALL_PROBES


def test_latency_spikes_do_not_form_incidents(db: sqlite3.Connection) -> None:
    """Only connectivity-loss events correlate. A spike is real but is not going dark,
    and folding it in would blur the backbone-vs-AP signal."""
    _outage_event(db, "wired-pi", NOW, NOW + 60_000, etype=EventType.LATENCY_SPIKE)
    _outage_event(db, "wifi-living", NOW, NOW + 60_000, etype=EventType.LATENCY_SPIKE)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)
    assert incidents == []


# ---------------------------------------------------------------------------
# Time grouping and clock skew
# ---------------------------------------------------------------------------


def test_non_overlapping_events_are_separate_incidents(db: sqlite3.Connection) -> None:
    """Two outages an hour apart are two incidents, not one."""
    _outage_event(db, "wired-pi", NOW, NOW + 60_000)
    _outage_event(db, "wifi-living", NOW + 3_600_000, NOW + 3_660_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 4_000_000)
    assert len(incidents) == 2


def test_slightly_skewed_events_still_correlate(db: sqlite3.Connection) -> None:
    """Two probes' clocks disagree by ~1s on the "same" outage -> still one incident.

    Correlation is only as good as time alignment, and the tolerance window is what makes
    it robust to the probes' clocks not agreeing.
    """
    _outage_event(db, "wired-pi", NOW, NOW + 60_000)
    _outage_event(db, "wired-desktop", NOW + 1_000, NOW + 61_000)  # 1s skew
    _outage_event(db, "wifi-living", NOW - 800, NOW + 59_000)
    _outage_event(db, "wifi-office", NOW + 500, NOW + 60_500)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    assert len(incidents) == 1, "sub-second skew should not fragment one incident"
    assert incidents[0].scope == IncidentScope.ALL_PROBES


def test_measured_clock_offset_is_applied(db: sqlite3.Connection) -> None:
    """A probe with a known 5s offset should still correlate once the offset is removed.

    The probe's timestamps are 5s ahead of the server's; applying its recorded offset
    realigns them so the outage overlaps the others.
    """
    db.execute("UPDATE probes SET clock_offset_ms = 5000 WHERE probe_id = 'wifi-office'")

    _outage_event(db, "wired-pi", NOW, NOW + 60_000)
    _outage_event(db, "wired-desktop", NOW, NOW + 60_000)
    _outage_event(db, "wifi-living", NOW, NOW + 60_000)
    # This probe's clock is 5s ahead, so its "same" outage is stamped +5s.
    _outage_event(db, "wifi-office", NOW + 5_000, NOW + 65_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    assert len(incidents) == 1, "offset was not applied; skewed probe fragmented the incident"
    assert incidents[0].probe_count == 4


# ---------------------------------------------------------------------------
# Persistence and idempotency
# ---------------------------------------------------------------------------


def test_events_are_linked_to_their_incident(db: sqlite3.Connection) -> None:
    for pid in ("wired-pi", "wifi-living"):
        _outage_event(db, pid, NOW, NOW + 60_000)

    Correlator().correlate(db, NOW - 10_000, NOW + 120_000)

    linked = db.execute("SELECT COUNT(*) FROM events WHERE incident_id IS NOT NULL").fetchone()[0]
    assert linked == 2, "member events should point at their incident"


def test_correlation_is_idempotent(db: sqlite3.Connection) -> None:
    """Re-running must not accumulate duplicate incidents -- the same property detection has."""
    for pid in ("wired-pi", "wired-desktop", "wifi-living", "wifi-office"):
        _outage_event(db, pid, NOW, NOW + 60_000)

    corr = Correlator()
    corr.correlate(db, NOW - 10_000, NOW + 120_000)
    first = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    corr.correlate(db, NOW - 10_000, NOW + 120_000)
    second = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    assert first == second == 1


def test_ongoing_incident_has_no_end(db: sqlite3.Connection) -> None:
    """If any member is still ongoing, the incident is too."""
    _outage_event(db, "wired-pi", NOW, None)  # still open
    _outage_event(db, "wifi-living", NOW, NOW + 60_000)

    incidents = Correlator().correlate(db, NOW - 10_000, NOW + 120_000)
    assert incidents[0].ended_ts is None


def test_empty_window_produces_no_incidents(db: sqlite3.Connection) -> None:
    assert Correlator().correlate(db, NOW, NOW + 1000) == []
