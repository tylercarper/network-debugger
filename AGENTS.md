# network-debugger — agent guide

Distributed monitoring to diagnose intermittent home network failures: random
disconnects and "full WiFi bars but no internet." Probes at several vantage points
(wired, and near each access point) report to a central server on a Raspberry Pi 4.

**The core diagnostic idea:** if an outage hits every probe at once it is the backbone;
if only the WiFi probes, the wireless infrastructure; if one probe, that AP or room.
Cross-probe scope classification is the system's primary output.

## Working process — read this first

**Invoke the `netdbg-workflow` skill at the start of any session.** It defines how work
is tracked and landed, and the process only works if it is followed across context
clears. In short:

- Work is tracked as **GitHub issues**. `./scripts/issues.sh list|get|new|comment|close`
- Anything deferred mid-work gets filed as an issue **immediately**, not carried in
  conversation.
- Changes land via **gated PRs**. `./scripts/pr.sh check|create|merge`
- Never push to `main`. Self-merge is per-session and off by default — check
  `./scripts/pr.sh may-i-merge`.
- A failing gate or post-merge action is debugged immediately.

## Layout

```
src/netdbg_common/   shared wire models, enums, monotonic clock
src/netdbg_agent/    probe: collectors, spool, shipper   (not yet built)
src/netdbg_server/   FastAPI, SQLite, detection, dashboard (not yet built)
scripts/             issues.sh, pr.sh
tests/               unit tests; fixtures/ holds captured real command output
```

## Invariants

These are load-bearing. Breaking one corrupts data in ways nothing downstream detects.

1. **`ts` is stamped at measurement and never modified.** UTC epoch ms. The server
   records `recv_ts` separately. Nothing infers measurement time from arrival time —
   samples routinely arrive hours late, because an outage is exactly when the server is
   unreachable.
2. **Timestamps derive from a monotonic anchor, not raw wall clock.** Wall clock jumps on
   NTP steps and wake-from-sleep. See `netdbg_common/timeutil.py`.
3. **The spool is durable (SQLite, synchronous commit).** A probe that crashes mid-outage
   must not lose the data that outage produced.
4. **Ingest is idempotent on `batch_id`.** Duplicate delivery is normal, not an edge case.
5. **Ship individual measurements, never agent-side aggregates.** Aggregates can be
   recomputed; discarded detail cannot.
6. **`SampleKind` integers are persisted — never renumber them.**
7. **Parsing is separated from execution.** Platform modules run a command and hand text
   to a pure parser, so all fragile parsing is testable on any machine.
8. **Collectors degrade, never crash.** A parser must return a degraded sample on
   malformed input; identity fields (SSID/BSSID) are permission-gated on every platform.

## Environment

Python 3.11+ via `uv`. Setup: `uv venv --python 3.11 && uv pip install -e '.[dev]'`.
Admin/root is available on all probe machines, so ICMP uses `icmplib(privileged=True)`
uniformly.
