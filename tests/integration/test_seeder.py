"""Seeder tests.

The seeder's value is not that it produces rows, but that it produces rows *shaped like
the real problem* -- containing each incident scope the correlation engine has to tell
apart. Uniform noise would make a detector that found nothing indistinguishable from one
that worked.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netdbg_server.seeder import seed

NOW = 1_700_000_000_000


@pytest.fixture
def seeded(tmp_path: Path) -> tuple[sqlite3.Connection, dict[str, int]]:
    db_path = tmp_path / "seeded.db"
    stats = seed(db_path, days=7, interval_ms=60_000, now_ms=NOW)
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn, stats


def test_generates_probes_across_groups(seeded: tuple[sqlite3.Connection, dict[str, int]]) -> None:
    """Scope classification needs probes in distinct groups to compare.

    With every probe in one group, an 'all_probes' incident and a 'single_ap' one would
    be indistinguishable.
    """
    conn, _ = seeded
    groups = {r["group_name"] for r in conn.execute("SELECT DISTINCT group_name FROM probes")}

    assert "wired" in groups
    assert "ap-living-room" in groups
    assert "ap-office" in groups


def test_wired_and_wifi_probes_both_present(
    seeded: tuple[sqlite3.Connection, dict[str, int]],
) -> None:
    """Exonerating WiFi requires a wired probe that stayed healthy through an incident."""
    conn, _ = seeded
    links = {r["link_type"] for r in conn.execute("SELECT DISTINCT link_type FROM probes")}
    assert {"wired", "wifi"} <= links


def test_seven_days_of_history(seeded: tuple[sqlite3.Connection, dict[str, int]]) -> None:
    conn, stats = seeded
    row = conn.execute("SELECT MIN(ts) AS lo, MAX(ts) AS hi FROM samples").fetchone()
    span_days = (row["hi"] - row["lo"]) / 86_400_000

    assert 6.9 < span_days <= 7.0
    assert stats["samples"] > 0


def test_contains_failures_and_successes(
    seeded: tuple[sqlite3.Connection, dict[str, int]],
) -> None:
    """All-success data would let a broken detector look correct."""
    conn, _ = seeded
    row = conn.execute("SELECT SUM(success) AS ok, SUM(1 - success) AS bad FROM samples").fetchone()

    assert row["ok"] > 0
    assert row["bad"] > 0
    # Failures should be the exception, as on a real network -- otherwise the partial
    # failures index and detection thresholds are being tuned against the wrong shape.
    assert row["bad"] / (row["ok"] + row["bad"]) < 0.2


def test_contains_a_correlated_multi_probe_incident(
    seeded: tuple[sqlite3.Connection, dict[str, int]],
) -> None:
    """There must be at least one moment where every group failed together.

    That is the backbone signature -- the thing cross-probe correlation exists to
    identify -- so the seeded data has to contain it.
    """
    conn, _ = seeded
    row = conn.execute(
        """
        SELECT s.ts, COUNT(DISTINCT p.group_name) AS groups_down
        FROM samples s JOIN probes p ON p.probe_id = s.probe_id
        WHERE s.success = 0
        GROUP BY s.ts
        ORDER BY groups_down DESC
        LIMIT 1
        """
    ).fetchone()

    assert row is not None
    assert row["groups_down"] >= 3, "no incident affecting all groups was generated"


def test_contains_gateway_up_internet_down(
    seeded: tuple[sqlite3.Connection, dict[str, int]],
) -> None:
    """The user's headline symptom must appear in the data.

    A moment where the gateway answers while both external anchors fail. Without it, the
    detector for the most important case cannot be developed or verified.
    """
    conn, _ = seeded
    row = conn.execute(
        """
        SELECT s.ts,
               SUM(CASE WHEN t.address = 'gateway' AND s.success = 1
                        THEN 1 ELSE 0 END) AS gw_ok,
               SUM(CASE WHEN t.address LIKE 'anchor%' AND s.success = 0
                        THEN 1 ELSE 0 END) AS anchors_down
        FROM samples s
        JOIN targets t ON t.target_id = s.target_id
        GROUP BY s.ts
        HAVING gw_ok > 0 AND anchors_down > 0
        LIMIT 1
        """
    ).fetchone()

    assert row is not None, "no gateway-up-internet-down window was generated"


def test_single_ap_incident_exists(seeded: tuple[sqlite3.Connection, dict[str, int]]) -> None:
    """One group failing alone -- an AP or its backhaul, not the backbone."""
    conn, _ = seeded
    row = conn.execute(
        """
        SELECT s.ts, COUNT(DISTINCT p.group_name) AS groups_down
        FROM samples s JOIN probes p ON p.probe_id = s.probe_id
        WHERE s.success = 0
        GROUP BY s.ts
        HAVING groups_down = 1
        LIMIT 1
        """
    ).fetchone()

    assert row is not None, "no single-group incident was generated"


def test_is_reproducible(tmp_path: Path) -> None:
    """A fixed seed must produce identical data.

    Otherwise a detection test that passes today fails tomorrow for reasons unrelated to
    the detector.
    """
    a = seed(tmp_path / "a.db", days=2, interval_ms=60_000, now_ms=NOW)
    b = seed(tmp_path / "b.db", days=2, interval_ms=60_000, now_ms=NOW)

    assert a == b

    def checksum(p: Path) -> int:
        conn = sqlite3.connect(p)
        return int(
            conn.execute(
                "SELECT COALESCE(SUM(success * 31 + CAST(ts % 1000 AS INTEGER)), 0) FROM samples"
            ).fetchone()[0]
        )

    assert checksum(tmp_path / "a.db") == checksum(tmp_path / "b.db")


def test_timestamps_are_plausible_epoch_ms(
    seeded: tuple[sqlite3.Connection, dict[str, int]],
) -> None:
    """Guards against a seconds/milliseconds mix-up, which is silent and corrupting."""
    conn, _ = seeded
    lo = conn.execute("SELECT MIN(ts) AS lo FROM samples").fetchone()["lo"]
    assert 1_600_000_000_000 < lo < 2_500_000_000_000
