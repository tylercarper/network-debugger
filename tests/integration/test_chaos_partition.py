"""End-to-end partition and heal.

This is the least-tested and most important reliability path in the system: the server
sits behind the network being debugged, so it is unreachable *exactly* when the data
matters most. If backfill loses or mangles anything, it loses the evidence for the very
outage it was supposed to explain.

The test partitions a probe from a real server, keeps measuring throughout, then heals
and asserts **zero loss and unmodified timestamps** -- the green-when condition from #6.

A real HTTP server on a real socket is used rather than a mocked transport. The
behaviour under test is the interaction between claim/confirm and batch_id idempotency,
and a mock would only confirm my own assumptions back to me.
"""

from __future__ import annotations

import socket
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest
import uvicorn

from netdbg_agent.collectors.icmp import IcmpTarget
from netdbg_agent.config import AgentConfig
from netdbg_agent.runner import AgentRunner
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_server.config import ServerConfig
from netdbg_server.main import create_app

NOW = 1_700_000_000_000

# Any address that will not answer. The partition is simulated by pointing the agent
# here, which exercises the real transport-failure path rather than a stubbed exception.
BLACKHOLE = "http://127.0.0.1:1"


class FakeHost:
    def __init__(self, alive: bool, rtts: list[float]) -> None:
        self.is_alive = alive
        self.rtts = rtts


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class LiveServer:
    url: str
    db_path: Path

    def db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    db_path = tmp_path / "server.db"
    port = _free_port()
    config = uvicorn.Config(
        create_app(ServerConfig(db_path=db_path)), host="127.0.0.1", port=port, log_level="error"
    )
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()

    deadline = time.time() + 10
    while not uv.started and time.time() < deadline:
        time.sleep(0.05)
    if not uv.started:
        raise RuntimeError("test server failed to start")

    try:
        yield LiveServer(url=f"http://127.0.0.1:{port}", db_path=db_path)
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def make_runner(tmp_path: Path) -> Iterator[Callable[..., AgentRunner]]:
    """Builds runners and closes their clients at teardown, so sockets do not leak."""
    created: list[AgentRunner] = []

    def _make(server_url: str, name: str, spool: Spool | None = None) -> AgentRunner:
        cfg = AgentConfig(server_url=server_url, name=name, ship_batch_size=500)
        s = spool if spool is not None else Spool(tmp_path / f"{name}-spool.db")
        runner = AgentRunner(
            config=cfg,
            spool=s,
            shipper=Shipper(cfg, s),
            targets=[
                IcmpTarget(address="192.0.2.1", label="gateway"),
                IcmpTarget(address="192.0.2.2", label="anchor-primary"),
            ],
        )
        created.append(runner)
        return runner

    yield _make
    for r in created:
        r.shipper.close()


def _server_counts(server: LiveServer) -> tuple[int, int | None, int | None]:
    row = (
        server.db()
        .execute("SELECT COUNT(*) AS n, MIN(ts) AS oldest, MAX(ts) AS newest FROM samples")
        .fetchone()
    )
    return row["n"], row["oldest"], row["newest"]


# ---------------------------------------------------------------------------
# The green-when condition
# ---------------------------------------------------------------------------


def test_partition_then_heal_loses_nothing(
    server: LiveServer, tmp_path: Path, make_runner: Callable[..., AgentRunner]
) -> None:
    """Measure across a partition, heal, and assert nothing was lost or altered.

    Three phases, each corresponding to a real moment: healthy operation, the outage
    itself, and recovery. The assertion that matters is on the third -- the data
    captured *during* the outage has to arrive intact, because that is the data that
    explains it.
    """
    spool = Spool(tmp_path / "partition-spool.db")

    # --- phase 1: healthy ---
    online = make_runner(server.url, "chaos-probe", spool=spool)
    assert online.ensure_registered(), "probe could not register"

    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [5.0])):
        for _ in range(5):
            online.collect_once()
    online.ship_if_due(now_mono=1e9)

    healthy_count, _, _ = _server_counts(server)
    assert healthy_count == 10, "baseline samples did not arrive"

    # --- phase 2: partitioned ---
    # The probe keeps measuring -- and the measurements now record failures, which is
    # the payload the outage produces and the thing most at risk of being lost.
    offline = make_runner(BLACKHOLE, "chaos-probe", spool=spool)

    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
        for _ in range(30):
            offline.collect_once()
            offline.ship_if_due(now_mono=1e9)

    assert spool.pending_count() == 60, "measurements lost while partitioned"
    assert _server_counts(server)[0] == healthy_count, "server should have received nothing"

    # --- phase 3: healed ---
    recovered = make_runner(server.url, "chaos-probe", spool=spool)
    for _ in range(20):
        if spool.pending_count() == 0:
            break
        recovered.ship_if_due(now_mono=1e9 + 10_000)

    assert spool.pending_count() == 0, "backfill did not drain the spool"

    final_count, _, _ = _server_counts(server)
    assert final_count == 70, f"expected 70 samples after heal, got {final_count}"

    failures = (
        server.db().execute("SELECT COUNT(*) AS n FROM samples WHERE success = 0").fetchone()["n"]
    )
    assert failures == 60, "the failure measurements from the outage did not survive"


def test_backfilled_timestamps_are_unmodified(
    server: LiveServer, tmp_path: Path, make_runner: Callable[..., AgentRunner]
) -> None:
    """Timestamps must survive the round trip exactly.

    If backfill nudged them, an outage would be recorded at the moment connectivity
    *returned* rather than when it broke -- precisely inverted from what is needed to
    diagnose it, and wrong in a way nothing downstream could detect.
    """
    spool = Spool(tmp_path / "ts-spool.db")
    runner = make_runner(server.url, "ts-probe", spool=spool)
    assert runner.ensure_registered()

    # Spool measurements stamped six hours ago, as a probe recovering from a long
    # outage would hold.
    outage_start = NOW - 6 * 3_600_000
    from netdbg_common.enums import SampleKind
    from netdbg_common.models import Sample

    original = [
        Sample(
            ts=outage_start + i * 1000,
            kind=SampleKind.ICMP,
            target="gateway",
            success=False,
        )
        for i in range(100)
    ]
    spool.add_samples(original)

    runner.ship_if_due(now_mono=1e9)
    assert spool.pending_count() == 0

    stored = [r["ts"] for r in server.db().execute("SELECT ts FROM samples ORDER BY ts")]

    assert stored == [s.ts for s in original], "timestamps altered during backfill"

    # recv_ts must record real arrival, so its distance from ts measures how long the
    # probe->server path was broken. That gap is a signal, not noise.
    gap = server.db().execute("SELECT MAX(recv_ts - ts) AS g FROM samples").fetchone()["g"]
    assert gap > 5 * 3_600_000, "recv_ts should reflect actual arrival, not measurement time"


def test_repeated_partitions_do_not_duplicate(
    server: LiveServer, tmp_path: Path, make_runner: Callable[..., AgentRunner]
) -> None:
    """Recovery is rarely clean; a flapping link must still converge exactly once.

    Each failed ship releases its claim and retries under a new batch_id, so this also
    exercises the server's idempotency under genuine retry rather than a synthetic
    replay.
    """
    spool = Spool(tmp_path / "flap-spool.db")
    online = make_runner(server.url, "flap-probe", spool=spool)
    assert online.ensure_registered()
    offline = make_runner(BLACKHOLE, "flap-probe", spool=spool)

    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [3.0])):
        for cycle in range(12):
            (offline if cycle % 2 == 0 else online).collect_once()
            # Alternate which runner attempts delivery, simulating a link going up and
            # down between cycles.
            (offline if cycle % 2 == 0 else online).ship_if_due(now_mono=1e9 + cycle * 10_000)

    for i in range(30):
        if spool.pending_count() == 0:
            break
        online.ship_if_due(now_mono=1e9 + 500_000 + i * 10_000)

    assert spool.pending_count() == 0
    assert _server_counts(server)[0] == 24, "flapping produced duplicate or missing rows"


def test_probe_started_during_outage_still_collects(
    tmp_path: Path, make_runner: Callable[..., AgentRunner]
) -> None:
    """A probe brought up mid-outage must record what it sees.

    Registration cannot succeed while the server is unreachable, so if collection were
    gated on it the probe would observe the entire outage and remember none of it.
    """
    spool = Spool(tmp_path / "cold-start.db")
    runner = make_runner(BLACKHOLE, "cold-probe", spool=spool)

    assert not runner.ensure_registered(), "should not register against a dead server"

    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
        for _ in range(10):
            runner.collect_once()
            runner.ship_if_due(now_mono=1e9)

    assert spool.pending_count() == 20, "an unregistered probe must still collect"


def test_agent_restart_mid_outage_keeps_data(
    server: LiveServer, tmp_path: Path, make_runner: Callable[..., AgentRunner]
) -> None:
    """A crash during an outage must not cost the buffered measurements.

    This is the case that justifies a durable spool over an in-memory queue: the probe
    holds the only copy, and the restart happens while the server is still unreachable.
    """
    spool_path = tmp_path / "restart-spool.db"

    spool1 = Spool(spool_path)
    offline = make_runner(BLACKHOLE, "restart-probe", spool=spool1)
    with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
        for _ in range(15):
            offline.collect_once()
    buffered = spool1.pending_count()
    assert buffered == 30
    spool1.close()  # process dies here

    # New process, same spool.
    spool2 = Spool(spool_path)
    assert spool2.pending_count() == buffered, "spooled data lost across restart"

    recovered = make_runner(server.url, "restart-probe", spool=spool2)
    assert recovered.ensure_registered()
    for _ in range(10):
        if spool2.pending_count() == 0:
            break
        recovered.ship_if_due(now_mono=1e9)

    assert _server_counts(server)[0] == buffered
