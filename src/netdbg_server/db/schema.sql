-- netdbg schema.
--
-- Sizing drives most of the decisions here. Roughly 5 probes x ~4 samples/s is about
-- 1.7M rows/day into `samples`, so that table is kept deliberately narrow: integer
-- columns only, no JSON, no repeated strings. Everything wide or textual lives in a
-- side table keyed off it. At ~60 bytes/row that is ~100MB/day, which a USB SSD handles
-- comfortably for a 7-day raw window plus indefinite rollups.
--
-- Timestamps are UTC epoch milliseconds, stored as INTEGER. `ts` is the agent's
-- measurement time and is never modified after insert; `recv_ts` is when the server
-- received it. The gap between them is itself diagnostic -- it measures how long the
-- probe->server path was broken -- so both are kept.

-- ---------------------------------------------------------------------------
-- Probes
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS probes (
    probe_id        TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    display_name    TEXT,
    group_name      TEXT,
    location        TEXT,
    link_type       TEXT NOT NULL DEFAULT 'unknown',
    os_name         TEXT,
    os_version      TEXT,
    agent_version   TEXT,
    capabilities    TEXT NOT NULL DEFAULT '[]',
    auth_token_hash TEXT,
    status          TEXT NOT NULL DEFAULT 'active',

    -- Estimated agent-vs-server skew. Recorded for correlation confidence only;
    -- it is never used to rewrite `ts`, which stays exactly as the agent stamped it.
    clock_offset_ms INTEGER NOT NULL DEFAULT 0,

    first_seen_ts   INTEGER NOT NULL,
    last_seen_ts    INTEGER,
    notes           TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS ix_probes_status ON probes(status);

-- ---------------------------------------------------------------------------
-- Targets
-- ---------------------------------------------------------------------------
-- A lookup table so the hot `samples` table stores a small integer instead of
-- repeating '1.1.1.1' two million times a day. Meaningful savings in both file size
-- and index size at this row count.

CREATE TABLE IF NOT EXISTS targets (
    target_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      INTEGER NOT NULL,
    address   TEXT NOT NULL,
    label     TEXT,
    UNIQUE (kind, address)
) STRICT;

-- ---------------------------------------------------------------------------
-- Samples (hot table)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS samples (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id         TEXT NOT NULL REFERENCES probes(probe_id),
    ts               INTEGER NOT NULL,
    recv_ts          INTEGER NOT NULL,
    kind             INTEGER NOT NULL,
    target_id        INTEGER NOT NULL REFERENCES targets(target_id),
    success          INTEGER NOT NULL,
    value_ms         REAL,
    code             INTEGER,
    seq              INTEGER,

    -- How far this sample's actual interval overran its schedule. A busy host delays
    -- the sampling loop and delayed samples look like failures; detection excludes
    -- samples whose slip exceeds a threshold rather than reporting a phantom outage.
    interval_slip_ms INTEGER,

    -- Host clock sync state at measurement. Cross-probe correlation is only as good as
    -- time alignment, so confidence is degraded when this is 0.
    ntp_synced       INTEGER
) STRICT;

-- Primary access pattern: one probe over a time range.
CREATE INDEX IF NOT EXISTS ix_samples_probe_ts ON samples(probe_id, ts);

-- Cross-probe correlation scans a time range across all probes.
CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);

-- Per-target series for the dashboard (e.g. RTT to 1.1.1.1 over time).
CREATE INDEX IF NOT EXISTS ix_samples_kind_target_ts ON samples(kind, target_id, ts);

-- Partial index over failures only. Nearly every diagnostic query is "show me the
-- failures", and in a table that is ~99% successes this index stays tiny while making
-- those queries effectively instant.
CREATE INDEX IF NOT EXISTS ix_samples_failures ON samples(ts) WHERE success = 0;

-- ---------------------------------------------------------------------------
-- WiFi samples
-- ---------------------------------------------------------------------------
-- Separate from `samples` because these rows are wide and only WiFi probes produce
-- them; folding them in would bloat the hot table for every probe.

CREATE TABLE IF NOT EXISTS wifi_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id        TEXT NOT NULL REFERENCES probes(probe_id),
    ts              INTEGER NOT NULL,
    recv_ts         INTEGER NOT NULL,

    -- Identity fields are nullable by design, not oversight: every platform gates
    -- SSID/BSSID behind a permission, and macOS exposes no BSSID at all via the
    -- supported path. `degraded_fields` records what was unavailable so the dashboard
    -- can show "unavailable here" rather than implying missing data.
    ssid            TEXT,
    bssid           TEXT,

    rssi_dbm        INTEGER,
    noise_dbm       INTEGER,
    snr_db          INTEGER,
    channel         INTEGER,
    band            TEXT,
    width_mhz       INTEGER,
    tx_rate_mbps    REAL,
    rx_rate_mbps    REAL,
    mcs             INTEGER,
    nss             INTEGER,
    tx_retries      INTEGER,
    tx_failed       INTEGER,
    beacon_loss     INTEGER,
    source          TEXT NOT NULL,
    degraded_fields TEXT NOT NULL DEFAULT '[]'
) STRICT;

CREATE INDEX IF NOT EXISTS ix_wifi_probe_ts ON wifi_samples(probe_id, ts);

-- Roam detection walks BSSID transitions over time.
CREATE INDEX IF NOT EXISTS ix_wifi_bssid_ts ON wifi_samples(bssid, ts);

-- ---------------------------------------------------------------------------
-- Incidents and events
-- ---------------------------------------------------------------------------
-- Incidents are declared before events because events reference them.

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_ts  INTEGER NOT NULL,
    ended_ts    INTEGER,

    -- The system's primary output: all_probes -> backbone, wifi_only -> wireless
    -- infrastructure, single_ap -> that AP or its backhaul, single_probe -> local/RF.
    scope       TEXT NOT NULL,

    probe_count INTEGER NOT NULL DEFAULT 0,
    summary     TEXT,
    hypothesis  TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS ix_incidents_time ON incidents(started_ts, ended_ts);

CREATE TABLE IF NOT EXISTS events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id     TEXT REFERENCES probes(probe_id),  -- NULL for server-level events
    incident_id  INTEGER REFERENCES incidents(incident_id),
    event_type   TEXT NOT NULL,
    subtype      TEXT,
    severity     TEXT NOT NULL,
    confidence   REAL NOT NULL,
    started_ts   INTEGER NOT NULL,
    ended_ts     INTEGER,
    duration_ms  INTEGER,

    -- The sample values that triggered this detection, so it can be audited rather
    -- than trusted.
    evidence     TEXT NOT NULL DEFAULT '{}',

    -- Which detector version produced this, so events from a superseded rule can be
    -- found and re-derived after the rule improves.
    detector_ver INTEGER NOT NULL DEFAULT 1,

    -- Detection re-runs over stored samples, including when backfilled data arrives
    -- late and rewinds a probe's watermark. This constraint makes re-detection an
    -- idempotent upsert instead of a source of duplicates.
    UNIQUE (probe_id, event_type, started_ts)
) STRICT;

CREATE INDEX IF NOT EXISTS ix_events_time ON events(started_ts, ended_ts);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type, started_ts);
CREATE INDEX IF NOT EXISTS ix_events_incident ON events(incident_id);

-- ---------------------------------------------------------------------------
-- Traceroutes
-- ---------------------------------------------------------------------------
-- Event-triggered and rate-limited, so volume is low and JSON hops are fine here.
-- This is the payload that localizes *where* a path broke: hop 1 answering while
-- hop 2 is silent implicates the ISP; hop 1 silent while direct gateway ping works
-- implicates the router's forwarding plane -- the classic "full bars, no internet".

CREATE TABLE IF NOT EXISTS traceroutes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id TEXT NOT NULL REFERENCES probes(probe_id),
    ts       INTEGER NOT NULL,
    target   TEXT NOT NULL,
    event_id INTEGER REFERENCES events(event_id),
    hops     TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS ix_traceroutes_probe_ts ON traceroutes(probe_id, ts);
CREATE INDEX IF NOT EXISTS ix_traceroutes_event ON traceroutes(event_id);

-- ---------------------------------------------------------------------------
-- Annotations
-- ---------------------------------------------------------------------------
-- User-recorded ground truth ("rebooted the router", "Netflix dropped"). This is the
-- label set that makes everything else interpretable -- without it we have events with
-- no confirmation of whether they corresponded to anything the user actually noticed.

CREATE TABLE IF NOT EXISTS annotations (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts   INTEGER NOT NULL,
    text TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS ix_annotations_ts ON annotations(ts);

-- ---------------------------------------------------------------------------
-- Rollups
-- ---------------------------------------------------------------------------
-- WITHOUT ROWID: the primary key *is* the access pattern, so this avoids maintaining
-- a second B-tree per table.
--
-- Raw samples are pruned after a retention window but rollups are kept indefinitely,
-- which is what makes long-horizon questions ("worse on Sunday evenings?") answerable
-- without storing months of raw data.

CREATE TABLE IF NOT EXISTS samples_1m (
    probe_id  TEXT NOT NULL,
    kind      INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    bucket_ts INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    n_ok      INTEGER NOT NULL,
    min_ms    REAL,
    p50_ms    REAL,
    p95_ms    REAL,
    max_ms    REAL,
    PRIMARY KEY (probe_id, kind, target_id, bucket_ts)
) WITHOUT ROWID, STRICT;

CREATE INDEX IF NOT EXISTS ix_samples_1m_bucket ON samples_1m(bucket_ts);

CREATE TABLE IF NOT EXISTS samples_1h (
    probe_id  TEXT NOT NULL,
    kind      INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    bucket_ts INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    n_ok      INTEGER NOT NULL,
    min_ms    REAL,
    p50_ms    REAL,
    p95_ms    REAL,
    max_ms    REAL,
    PRIMARY KEY (probe_id, kind, target_id, bucket_ts)
) WITHOUT ROWID, STRICT;

CREATE INDEX IF NOT EXISTS ix_samples_1h_bucket ON samples_1h(bucket_ts);

-- ---------------------------------------------------------------------------
-- Ingest deduplication
-- ---------------------------------------------------------------------------
-- The agent retries across a flapping network and cannot know whether a request that
-- timed out was actually applied, so duplicate delivery is the normal case rather than
-- an edge case. Recording applied batch ids makes ingest idempotent.

CREATE TABLE IF NOT EXISTS ingest_batches (
    batch_id    TEXT PRIMARY KEY,
    probe_id    TEXT NOT NULL REFERENCES probes(probe_id),
    recv_ts     INTEGER NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX IF NOT EXISTS ix_ingest_batches_recv ON ingest_batches(recv_ts);

-- ---------------------------------------------------------------------------
-- Detection watermarks
-- ---------------------------------------------------------------------------
-- How far detection has processed per probe. Backfilled data arriving with timestamps
-- older than the watermark rewinds it, so the affected window is re-detected rather
-- than skipped -- which is what makes late-arriving outage data actually get analyzed.

CREATE TABLE IF NOT EXISTS detect_watermarks (
    probe_id           TEXT PRIMARY KEY REFERENCES probes(probe_id),
    detected_through_ts INTEGER NOT NULL
) STRICT;
