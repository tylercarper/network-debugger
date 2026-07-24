"""Time-series read endpoint for the dashboard.

The timeline view needs, per probe and per target, a success rate and a representative
RTT over time. Returning raw samples would be fatal at scale: a 7-day window across four
probes and three targets is millions of rows, far more than a browser can plot. So this
buckets server-side and **auto-selects the bucket size from the window width**, keeping the
point count roughly constant regardless of how far the user zoomed out.

Buckets carry three numbers the timeline actually renders:

* ``ok_rate`` -- fraction of samples in the bucket that succeeded. This drives the status
  ribbon colour (green/degraded/red), which is what makes the correlation readable at a
  glance.
* ``p50_ms`` / ``max_ms`` -- median and worst RTT, so a latency problem is visible without
  shipping every point.

Aggregating in SQL rather than in Python keeps the whole thing to one query per request
even over a week of data.
"""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Request

from netdbg_common.enums import SampleKind
from netdbg_common.timeutil import utc_now_ms

router = APIRouter(prefix="/api/v1", tags=["series"])

# Target bucket count. The bucket size is chosen so a window yields about this many
# points -- enough to see structure, few enough to plot smoothly.
_TARGET_BUCKETS = 300

# Never bucket finer than the real sample cadence (~1s) -- smaller buckets would just be
# mostly-empty and waste points.
_MIN_BUCKET_MS = 1_000

# Sub-bucket width for the worst-case ribbon computation. This is a deliberate tension:
# too small and a single isolated dropped packet dominates the sub-bucket's rate and
# speckles the ribbon with false "loss"; too large and a short outage is diluted. 60s
# holds enough samples (~60 at 1s cadence, ~6 at the seed's 10s) that one stray drop lands
# around 0.85-0.98 -- comfortably "ok" -- while a genuine sustained outage drives the
# sub-bucket toward 0. Independent of the display bucket, then floored to it.
_WORST_SUB_MS = 60_000

# A sub-bucket with fewer than this many samples is ignored for the worst-case rate: with
# only one or two samples a single drop looks like catastrophic loss, which is noise, not
# signal. Sub-buckets this sparse fall back to contributing nothing to `worst`.
_WORST_MIN_SAMPLES = 3


def _db(request: Request) -> sqlite3.Connection:
    conn: sqlite3.Connection = request.app.state.db
    return conn


def _bucket_ms(from_ts: int, to_ts: int) -> int:
    """Pick a bucket width that yields ~_TARGET_BUCKETS points over the window."""
    span = max(1, to_ts - from_ts)
    raw = span // _TARGET_BUCKETS
    return max(_MIN_BUCKET_MS, raw)


@router.get("/series")
def series(
    request: Request,
    from_ts: int,
    to_ts: int,
    kind: int = int(SampleKind.ICMP),
) -> dict[str, object]:
    """Bucketed success-rate and RTT per probe/target over a window.

    Shape is designed for direct consumption by the timeline: a flat list of series, each
    keyed by (probe, target), each with parallel arrays uPlot can plot without reshaping.
    """
    conn = _db(request)
    bucket = _bucket_ms(from_ts, to_ts)

    # A finer sub-bucket used only to compute the *worst* moment within each display
    # bucket. This is what stops a short-but-total outage from being averaged away: at a
    # 7-day zoom a display bucket is ~30 minutes, and a 60-second outage inside it would
    # barely move the average ok_rate. The ribbon must colour by the worst sub-bucket, so
    # the outage still paints the bucket red. The sub-bucket is the real sample cadence,
    # floored so it never exceeds the display bucket.
    sub = min(bucket, max(_MIN_BUCKET_MS, _WORST_SUB_MS))

    # First pass: per sub-bucket success rate.
    sub_rows = conn.execute(
        """
        SELECT
            s.probe_id                              AS probe_id,
            COALESCE(p.display_name, p.name)        AS probe_name,
            p.group_name                            AS group_name,
            p.link_type                             AS link_type,
            t.address                               AS target,
            (s.ts / ?) * ?                          AS bucket_ts,
            (s.ts / ?) * ?                          AS sub_ts,
            COUNT(*)                                AS n,
            SUM(s.success)                          AS n_ok,
            AVG(CASE WHEN s.success THEN s.value_ms END) AS avg_ms,
            MAX(CASE WHEN s.success THEN s.value_ms END) AS max_ms
        FROM samples s
        JOIN probes p  ON p.probe_id = s.probe_id
        JOIN targets t ON t.target_id = s.target_id
        WHERE s.kind = ? AND s.ts >= ? AND s.ts <= ?
        GROUP BY s.probe_id, t.target_id, bucket_ts, sub_ts
        ORDER BY s.probe_id, t.address, bucket_ts, sub_ts
        """,
        (bucket, bucket, sub, sub, kind, from_ts, to_ts),
    ).fetchall()

    # Roll sub-buckets up into display buckets, keeping both the average ok_rate (for the
    # overview) and the *minimum* sub-bucket ok_rate (for the ribbon colour).
    agg: dict[tuple[str, str, int], dict[str, float]] = {}
    meta: dict[str, sqlite3.Row] = {}
    for r in sub_rows:
        key = (r["probe_id"], r["target"], r["bucket_ts"])
        meta[r["probe_id"]] = r
        a = agg.setdefault(
            key,
            {"n": 0, "n_ok": 0, "worst": 1.0, "avg_sum": 0.0, "avg_cnt": 0.0, "max_ms": 0.0},
        )
        n = r["n"] or 0
        n_ok = r["n_ok"] or 0
        a["n"] += n
        a["n_ok"] += n_ok
        # Only sub-buckets with enough samples contribute to the worst-case rate, so a
        # lone dropped packet in a near-empty sub-bucket does not paint the ribbon.
        if n >= _WORST_MIN_SAMPLES:
            a["worst"] = min(a["worst"], n_ok / n)
        if r["avg_ms"] is not None:
            a["avg_sum"] += r["avg_ms"] * (n_ok or 1)
            a["avg_cnt"] += n_ok or 1
        if r["max_ms"] is not None:
            a["max_ms"] = max(a["max_ms"], r["max_ms"])

    rows = [
        {
            "probe_id": pid,
            "probe_name": meta[pid]["probe_name"],
            "group_name": meta[pid]["group_name"],
            "link_type": meta[pid]["link_type"],
            "target": target,
            "bucket_ts": bts,
            "n": a["n"],
            "n_ok": a["n_ok"],
            "worst_ok": round(a["worst"], 3),
            "avg_ms": (a["avg_sum"] / a["avg_cnt"]) if a["avg_cnt"] else None,
            "max_ms": a["max_ms"] if a["max_ms"] else None,
        }
        for (pid, target, bts), a in agg.items()
    ]

    # Reshape into one series per (probe, target) with parallel arrays. Sort by
    # (probe, target, bucket_ts) first -- the sub-bucket rollup above is dict-ordered, and
    # the timeline needs buckets in ascending time to place them on the x-axis.
    rows.sort(key=lambda r: (str(r["probe_id"]), str(r["target"]), int(r["bucket_ts"])))

    series_map: dict[tuple[str, str], dict[str, object]] = {}
    for r in rows:
        series_key: tuple[str, str] = (str(r["probe_id"]), str(r["target"]))
        s = series_map.get(series_key)
        if s is None:
            s = {
                "probe_id": r["probe_id"],
                "probe_name": r["probe_name"],
                "group_name": r["group_name"],
                "link_type": r["link_type"],
                "target": r["target"],
                "bucket_ts": [],
                "ok_rate": [],
                "worst_ok": [],
                "avg_ms": [],
                "max_ms": [],
            }
            series_map[series_key] = s
        n = int(r["n"] or 0)
        n_ok = int(r["n_ok"] or 0)
        avg_ms = r["avg_ms"]
        max_ms = r["max_ms"]
        for field, value in (
            ("bucket_ts", r["bucket_ts"]),
            ("ok_rate", round(n_ok / n, 3) if n else None),
            # worst_ok drives the ribbon colour, so a brief total outage inside a coarse
            # bucket still registers as red rather than averaging to green.
            ("worst_ok", r["worst_ok"]),
            ("avg_ms", round(float(avg_ms), 1) if avg_ms is not None else None),
            ("max_ms", round(float(max_ms), 1) if max_ms is not None else None),
        ):
            arr = s[field]
            assert isinstance(arr, list)
            arr.append(value)

    return {
        "from_ts": from_ts,
        "to_ts": to_ts,
        "bucket_ms": bucket,
        "series": list(series_map.values()),
        "server_ts": utc_now_ms(),
    }
