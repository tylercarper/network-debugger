"""Synthetic history generator.

A seven-day timeline view and the rollup/retention logic cannot be developed against
twenty minutes of local data, so this fabricates a plausible history and unblocks server
and dashboard work in parallel with agent work.

The generated data is deliberately *shaped like the real problem*: it contains the
incident scopes the correlation engine has to distinguish. If the seeder only produced
uniform noise, a detector that found nothing would look identical to one that worked.
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from netdbg_common.enums import LinkType, SampleKind
from netdbg_common.models import ProbeInfo
from netdbg_server.db.engine import init_db, transaction
from netdbg_server.db.queries import get_or_create_target, upsert_probe

__all__ = ["SeedProbe", "seed"]

# Named so the fixtures cannot be confused with real infrastructure.
SEED_PROBES = [
    ("seed-pi-wired", "wired", LinkType.WIRED),
    ("seed-desktop-wired", "wired", LinkType.WIRED),
    ("seed-ap-living-room", "ap-living-room", LinkType.WIFI),
    ("seed-ap-office", "ap-office", LinkType.WIFI),
]

TARGETS = [
    ("gateway", 1.2, 0.8),  # label, baseline RTT ms, jitter ms
    ("anchor-primary", 12.0, 4.0),
    ("anchor-secondary", 14.0, 5.0),
]


@dataclass(frozen=True, slots=True)
class SeedProbe:
    probe_id: str
    name: str
    group: str
    link_type: LinkType


@dataclass(frozen=True, slots=True)
class _Incident:
    """A scripted failure window.

    ``affected`` names the probe groups involved, which is what makes each incident
    correspond to a distinct real-world cause:

    * every group      -> backbone (router / modem / ISP)
    * both wifi groups -> wireless infrastructure
    * one wifi group   -> a single AP or its backhaul
    """

    start_ms: int
    duration_ms: int
    affected: set[str]
    total: bool
    """True for a full outage; False for gateway-reachable-but-internet-down.

    The second case is the user's headline symptom, so the seeded data has to contain
    it or the detector for it cannot be developed.
    """


def _build_incidents(start_ms: int, days: int, rng: random.Random) -> list[_Incident]:
    """Script incidents covering every scope the correlation engine must classify."""
    incidents: list[_Incident] = []
    day_ms = 86_400_000
    all_groups = {"wired", "ap-living-room", "ap-office"}

    for day in range(days):
        day_start = start_ms + day * day_ms

        # Backbone outage, evenings -- the pattern a scheduled task or congestion makes.
        if day % 2 == 0:
            incidents.append(
                _Incident(
                    start_ms=day_start + 20 * 3_600_000 + rng.randint(0, 1_800_000),
                    duration_ms=rng.randint(45_000, 180_000),
                    affected=all_groups,
                    total=rng.random() < 0.5,
                )
            )

        # A single AP dropping -- looks identical to a backbone fault from one room,
        # which is exactly why cross-probe correlation is needed to tell them apart.
        if day % 3 == 0:
            incidents.append(
                _Incident(
                    start_ms=day_start + 14 * 3_600_000 + rng.randint(0, 3_600_000),
                    duration_ms=rng.randint(20_000, 90_000),
                    affected={"ap-office"},
                    total=True,
                )
            )

        # Both APs but neither wired probe -- the wireless side of the router.
        if day % 4 == 1:
            incidents.append(
                _Incident(
                    start_ms=day_start + 9 * 3_600_000,
                    duration_ms=rng.randint(30_000, 120_000),
                    affected={"ap-living-room", "ap-office"},
                    total=False,
                )
            )

    return incidents


def _sample_rows(
    probe: SeedProbe,
    target_label: str,
    target_id: int,
    baseline: float,
    jitter: float,
    start_ms: int,
    end_ms: int,
    interval_ms: int,
    incidents: list[_Incident],
    rng: random.Random,
) -> list[tuple[object, ...]]:
    rows: list[tuple[object, ...]] = []
    is_gateway = target_label == "gateway"

    for ts in range(start_ms, end_ms, interval_ms):
        active = next(
            (
                i
                for i in incidents
                if probe.group in i.affected and i.start_ms <= ts < i.start_ms + i.duration_ms
            ),
            None,
        )

        if active is not None and (active.total or not is_gateway):
            # During a gateway-up-internet-down incident the gateway keeps answering;
            # only the external anchors fail. That asymmetry is the whole signature.
            success, value = 0, None
        else:
            # Occasional isolated loss, so detection has to cope with noise rather than
            # treating any single failure as an incident.
            if rng.random() < 0.0008:
                success, value = 0, None
            else:
                rtt = rng.gauss(baseline, jitter)
                if probe.link_type is LinkType.WIFI:
                    rtt += abs(rng.gauss(0, 3.0))  # wifi is noisier
                success, value = 1, max(0.05, rtt)

        rows.append((probe.probe_id, ts, ts, int(SampleKind.ICMP), target_id, success, value))

    return rows


def seed(
    db_path: Path,
    days: int = 7,
    interval_ms: int = 10_000,
    now_ms: int | None = None,
    seed_value: int = 42,
) -> dict[str, int]:
    """Populate a database with synthetic history.

    ``interval_ms`` defaults to 10s rather than the real 1s: seven days at 1s across
    four probes and three targets is ~7M rows, which is slow to generate and unnecessary
    for developing views. Detection logic that needs true 1s resolution should use a
    shorter window instead.
    """
    rng = random.Random(seed_value)
    conn = init_db(db_path)

    # Anchor to a fixed timestamp when not given, so runs are reproducible.
    end_ms = now_ms if now_ms is not None else 1_700_000_000_000
    start_ms = end_ms - days * 86_400_000

    incidents = _build_incidents(start_ms, days, rng)
    probes = [
        SeedProbe(probe_id=f"seed-{name}", name=name, group=group, link_type=link)
        for name, group, link in SEED_PROBES
    ]

    total_rows = 0
    with transaction(conn):
        for probe in probes:
            upsert_probe(
                conn,
                probe.probe_id,
                ProbeInfo(
                    name=probe.name,
                    link_type=probe.link_type,
                    os_name="Linux",
                    agent_version="seed",
                    capabilities=["icmp.privileged"],
                ),
                start_ms,
            )
            conn.execute(
                "UPDATE probes SET group_name = ?, last_seen_ts = ? WHERE probe_id = ?",
                (probe.group, end_ms, probe.probe_id),
            )

        target_ids = {
            label: get_or_create_target(conn, SampleKind.ICMP, label) for label, _, _ in TARGETS
        }

    for probe in probes:
        for label, baseline, jitter in TARGETS:
            rows = _sample_rows(
                probe,
                label,
                target_ids[label],
                baseline,
                jitter,
                start_ms,
                end_ms,
                interval_ms,
                incidents,
                rng,
            )
            # Chunked so a multi-million-row seed does not build one enormous
            # transaction and stall.
            for i in range(0, len(rows), 10_000):
                with transaction(conn):
                    conn.executemany(
                        "INSERT INTO samples"
                        " (probe_id, ts, recv_ts, kind, target_id, success, value_ms)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?)",
                        rows[i : i + 10_000],
                    )
            total_rows += len(rows)

    conn.close()
    return {
        "probes": len(probes),
        "samples": total_rows,
        "incidents": len(incidents),
        "start_ms": start_ms,
        "end_ms": end_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic monitoring history")
    parser.add_argument("--db", type=Path, default=Path("/data/netdbg.db"))
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--interval-ms", type=int, default=10_000)
    parser.add_argument("--now-ms", type=int, default=None)
    args = parser.parse_args()

    # Guard on "has samples", not "file exists": the server's lifespan calls init_db on
    # startup, which creates a non-empty (schema-only) file before the seeder ever runs.
    # A file-existence guard would then always skip. What the guard actually protects
    # against is overlaying a second set of incidents on data that already has some.
    if args.db.exists() and args.db.stat().st_size > 0 and _has_samples(args.db):
        print(f"{args.db} already contains samples; skipping seed")
        return

    stats = seed(args.db, days=args.days, interval_ms=args.interval_ms, now_ms=args.now_ms)
    print(json.dumps(stats, indent=2))


def _has_samples(db_path: Path) -> bool:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='samples'"
        ).fetchone()
        if row is None:
            return False
        return int(conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]) > 0
    finally:
        conn.close()


if __name__ == "__main__":
    main()
