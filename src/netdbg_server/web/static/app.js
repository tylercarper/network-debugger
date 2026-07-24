// Dashboard logic. Vanilla JS, no build step, no dependencies.
//
// The flagship is the correlated multi-probe timeline: one status ribbon per probe on a
// shared x-axis. Read vertically, it answers the question at a glance -- red across every
// lane is the backbone; red only in the WiFi lanes is the wireless side; red in one lane
// is that AP. The lanes MUST share an x-axis or that correlation is lost, so all ribbons
// are built from the same time window and bucket grid.

const HOUR = 3600_000;
const RANGES = { "1h": HOUR, "6h": 6 * HOUR, "24h": 24 * HOUR, "7d": 7 * 24 * HOUR };

let rangeMs = RANGES["24h"];

// Status thresholds on a bucket's success rate. These are ordered STATE, not identity;
// each renders with a text label somewhere so meaning is never colour-alone.
function statusOf(okRate) {
  if (okRate === null || okRate === undefined) return "nodata";
  // Tuned against real data: the ribbon uses worst_ok (min success over a 60s sub-bucket),
  // so an isolated dropped packet lands around 0.85-0.98 and must read as "ok" -- otherwise
  // ordinary background loss speckles the ribbon and buries the real incidents. Only
  // substantial sustained loss earns a warning colour; near-total loss is an outage.
  if (okRate >= 0.75) return "good";
  if (okRate >= 0.5) return "warning";
  if (okRate >= 0.15) return "serious";
  return "critical";
}

// A probe's overall status = the worst status across its targets in the latest buckets.
const STATUS_RANK = { good: 0, warning: 1, serious: 2, critical: 3, nodata: -1 };

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}

function fmtAgo(ms) {
  if (ms == null) return "never";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

function fmtTime(ts) {
  return new Date(ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// --- overview: status tiles + recent incidents ---------------------------

async function renderOverview() {
  const health = await getJSON("/api/v1/health");
  const now = health.server_ts;

  // Pull a short recent window to compute each probe's live status from its samples.
  const from = now - 10 * 60_000;
  const seriesResp = await getJSON(`/api/v1/series?from_ts=${from}&to_ts=${now}`);
  const worstByProbe = {};
  for (const s of seriesResp.series) {
    const recent = s.ok_rate.slice(-3); // last few buckets
    for (const ok of recent) {
      const st = statusOf(ok);
      if (STATUS_RANK[st] > (STATUS_RANK[worstByProbe[s.probe_id]] ?? -2)) {
        worstByProbe[s.probe_id] = st;
      }
    }
  }

  const tiles = document.getElementById("tiles");
  tiles.innerHTML = "";
  for (const p of health.probes) {
    const stale = p.stale_ms == null || p.stale_ms > 120_000;
    const status = stale ? "critical" : (worstByProbe[p.probe_id] || "good");
    const badge = stale ? "stale" : status;
    const el = document.createElement("div");
    el.className = `tile ${status}`;
    el.innerHTML = `
      <div class="name">${escapeHtml(p.name)}
        <span class="badge ${badge}">${badge}</span></div>
      <div class="meta">last report: ${fmtAgo(p.stale_ms)}</div>`;
    tiles.appendChild(el);
  }
  if (!health.probes.length) {
    tiles.innerHTML = `<div class="empty">No probes have registered yet.</div>`;
  }

  // Recent incidents -- the "did something happen overnight" answer.
  const inc = await getJSON(`/api/v1/incidents?from_ts=${now - 7 * 24 * HOUR}&to_ts=${now}`);
  const box = document.getElementById("incidents");
  box.innerHTML = "";
  if (!inc.incidents.length) {
    box.innerHTML = `<div class="empty">No incidents in the last 7 days.</div>`;
  }
  for (const i of inc.incidents.slice(0, 10)) {
    let hyp = "";
    try { hyp = JSON.parse(i.hypothesis).hypothesis; } catch { hyp = ""; }
    const el = document.createElement("div");
    el.className = "incident";
    const dur = i.ended_ts ? `${Math.round((i.ended_ts - i.started_ts) / 1000)}s` : "ongoing";
    el.innerHTML = `
      <span class="scope ${i.scope}">${i.scope.replace(/_/g, " ")}</span>
      <div class="body">
        <div class="when">${fmtTime(i.started_ts)} · ${dur} · ${i.probe_count} probe(s)</div>
        <div class="hypothesis">${escapeHtml(hyp)}</div>
      </div>`;
    box.appendChild(el);
  }
}

// --- timeline: correlated multi-probe ribbons ----------------------------

async function renderTimeline() {
  const now = Date.now();
  const from = now - rangeMs;
  const resp = await getJSON(`/api/v1/series?from_ts=${from}&to_ts=${now}`);

  // Group series by probe, then merge each probe's targets into one worst-case ribbon:
  // a bucket is as bad as its worst target, because losing *any* path is the probe
  // losing connectivity.
  const byProbe = new Map();
  for (const s of resp.series) {
    if (!byProbe.has(s.probe_id)) {
      byProbe.set(s.probe_id, { name: s.probe_name, group: s.group_name, link: s.link_type, buckets: new Map() });
    }
    const p = byProbe.get(s.probe_id);
    s.bucket_ts.forEach((ts, idx) => {
      // Colour by the WORST moment in the bucket, not the average -- otherwise a brief
      // total outage inside a coarse (e.g. 30-min) bucket averages to green and the
      // incident vanishes from the timeline, which is the one thing the timeline exists
      // to show. worst_ok is the min success rate over 30s sub-buckets.
      const st = statusOf(s.worst_ok[idx]);
      const prev = p.buckets.get(ts);
      if (prev === undefined || STATUS_RANK[st] > STATUS_RANK[prev]) p.buckets.set(ts, st);
    });
  }

  const lanes = document.getElementById("lanes");
  lanes.innerHTML = "";

  if (byProbe.size === 0) {
    lanes.innerHTML = `<div class="empty">No sample data in this window.</div>`;
    return;
  }

  // A shared bucket grid across all lanes -- essential for the vertical correlation to
  // line up. Build the union of bucket timestamps, sorted.
  const allTs = new Set();
  for (const p of byProbe.values()) for (const ts of p.buckets.keys()) allTs.add(ts);
  const grid = [...allTs].sort((a, b) => a - b);

  // Sort lanes: wired first, then by group, so co-located probes sit together and the
  // wired-vs-wifi split is visually obvious.
  const probes = [...byProbe.entries()].sort((a, b) => {
    const la = a[1].link === "wired" ? 0 : 1, lb = b[1].link === "wired" ? 0 : 1;
    return la - lb || (a[1].group || "").localeCompare(b[1].group || "");
  });

  for (const [, p] of probes) {
    const lane = document.createElement("div");
    lane.className = "lane";
    const segs = grid.map((ts) => {
      const st = p.buckets.get(ts) || "nodata";
      return `<div class="seg ${st}" style="flex:1" title="${fmtTime(ts)}: ${st}"></div>`;
    }).join("");
    lane.innerHTML = `
      <div class="label">${escapeHtml(p.name)}<br><span class="grp">${escapeHtml(p.group || p.link || "")}</span></div>
      <div class="ribbon">${segs}</div>`;
    lanes.appendChild(lane);
  }

  // Shared x-axis ticks.
  const axis = document.getElementById("axis");
  if (grid.length) {
    const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
      const ts = grid[Math.min(grid.length - 1, Math.floor(f * (grid.length - 1)))];
      return `<span>${fmtTime(ts)}</span>`;
    }).join("");
    axis.innerHTML = `<div></div><div class="ticks">${ticks}</div>`;
  }
}

// --- wiring --------------------------------------------------------------

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function setRange(key, btn) {
  rangeMs = RANGES[key];
  document.querySelectorAll(".controls button").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  renderTimeline();
}

async function refresh() {
  try {
    await Promise.all([renderOverview(), renderTimeline()]);
    document.getElementById("status").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById("status").textContent = "error: " + e.message;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".controls button").forEach((btn) => {
    btn.addEventListener("click", () => setRange(btn.dataset.range, btn));
  });
  refresh();
  // Poll: SSE is a later refinement (#39). 15s matches the slowest collector cadence.
  setInterval(refresh, 15_000);
});
