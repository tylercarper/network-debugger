"""Shipper tests, run against a real HTTP server on a real socket.

These deliberately drive the actual FastAPI app over real HTTP rather than a mocked
transport. The interesting behaviour lives in the *interaction* between the two halves --
claim/confirm against batch_id idempotency, retry against duplicate detection -- and a
mock would only assert that the shipper does what I already believed it does.

A background uvicorn on an ephemeral port is used rather than httpx's ASGITransport,
which is async-only and cannot back the synchronous client the agent uses.
"""

from __future__ import annotations

import socket
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import uvicorn

from netdbg_agent.config import AgentConfig
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_common.enums import SampleKind
from netdbg_common.models import ProbeInfo, Sample
from netdbg_server.config import ServerConfig
from netdbg_server.main import create_app

NOW = 1_700_000_000_000


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
    cfg = ServerConfig(db_path=db_path, detection_interval_s=0)
    port = _free_port()
    config = uvicorn.Config(create_app(cfg), host="127.0.0.1", port=port, log_level="error")
    uv_server = uvicorn.Server(config)
    thread = threading.Thread(target=uv_server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10
    while not uv_server.started and time.time() < deadline:
        time.sleep(0.05)
    if not uv_server.started:
        raise RuntimeError("test server failed to start")

    try:
        yield LiveServer(url=f"http://127.0.0.1:{port}", db_path=db_path)
    finally:
        uv_server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def spool(tmp_path: Path) -> Iterator[Spool]:
    s = Spool(tmp_path / "spool.db")
    yield s
    s.close()


@pytest.fixture
def make_shipper() -> Iterator[Callable[..., Shipper]]:
    """Builds Shippers and closes their HTTP clients at teardown.

    Without this the connection pools leak sockets, which surfaces as
    PytestUnraisableExceptionWarning under filterwarnings=error.
    """
    created: list[Shipper] = []

    def _make(cfg: AgentConfig, spool: Spool, client: httpx.Client | None = None) -> Shipper:
        s = Shipper(cfg, spool, client=client)
        created.append(s)
        return s

    yield _make
    for s in created:
        s.close()


@pytest.fixture
def shipper(server: LiveServer, spool: Spool, make_shipper: Callable[..., Shipper]) -> Shipper:
    cfg = AgentConfig(server_url=server.url, name="test-probe")
    return make_shipper(cfg, spool)


def _samples(n: int, start: int = NOW, ok: bool = True) -> list[Sample]:
    return [
        Sample(ts=start + i * 1000, kind=SampleKind.ICMP, target="1.1.1.1", success=ok)
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_persists_identity(shipper: Shipper, spool: Spool) -> None:
    assert shipper.register(ProbeInfo(name="test-probe")) is True
    assert shipper.is_registered

    assert spool.get_identity("probe_id") == shipper.probe_id
    assert spool.get_identity("token") is not None


def test_restart_resumes_same_probe_identity(
    server: LiveServer, spool: Spool, make_shipper: Callable[..., Shipper]
) -> None:
    """A restart must not appear as a new probe and fragment its own history."""
    cfg = AgentConfig(server_url=server.url)

    s1 = make_shipper(cfg, spool)
    s1.register(ProbeInfo(name="p"))
    original_id = s1.probe_id

    # New Shipper over the same spool, as a restarted process would be.
    s2 = make_shipper(cfg, spool)
    assert s2.probe_id == original_id
    s2.register(ProbeInfo(name="p"))
    assert s2.probe_id == original_id


def test_registration_failure_is_not_fatal(
    spool: Spool, make_shipper: Callable[..., Shipper]
) -> None:
    """A probe started during an outage must still collect into its spool.

    Registration is retried; measurement does not wait for it.
    """
    cfg = AgentConfig(server_url="http://127.0.0.1:1")  # nothing listening
    shipper = make_shipper(cfg, spool, httpx.Client(timeout=0.1))

    assert shipper.register(ProbeInfo(name="p")) is False
    assert not shipper.is_registered

    spool.add_samples(_samples(5))
    assert spool.pending_count() == 5, "collection must continue regardless"


# ---------------------------------------------------------------------------
# Shipping
# ---------------------------------------------------------------------------


def test_ship_delivers_and_clears_spool(shipper: Shipper, spool: Spool) -> None:
    shipper.register(ProbeInfo(name="p"))
    spool.add_samples(_samples(10))

    result = shipper.ship_once(NOW)

    assert result.ok
    assert result.shipped == 10
    assert not result.duplicate
    assert spool.pending_count() == 0, "confirmed data should be released"


def test_ship_with_empty_spool_is_a_noop(shipper: Shipper) -> None:
    shipper.register(ProbeInfo(name="p"))
    result = shipper.ship_once(NOW)

    assert result.ok
    assert result.shipped == 0


def test_unregistered_shipper_does_not_ship(shipper: Shipper, spool: Spool) -> None:
    spool.add_samples(_samples(5))
    result = shipper.ship_once(NOW)

    assert not result.ok
    assert spool.pending_count() == 5, "data must be retained until it can be sent"


def test_backfill_preserves_timestamps_end_to_end(
    shipper: Shipper, spool: Spool, server: LiveServer
) -> None:
    """The full path: six-hour-old measurements spooled, shipped, and stored intact.

    This is the invariant the whole system rests on, exercised across every layer at
    once rather than asserted at each boundary in isolation.
    """
    shipper.register(ProbeInfo(name="p"))
    outage_start = NOW - 6 * 3_600_000
    spool.add_samples(_samples(100, start=outage_start, ok=False))

    assert shipper.ship_once(NOW).ok

    row = server.db().execute("SELECT MIN(ts) AS oldest, COUNT(*) AS n FROM samples").fetchone()

    assert row["n"] == 100
    assert row["oldest"] == outage_start, "timestamp altered somewhere in the pipeline"


# ---------------------------------------------------------------------------
# Failure handling -- data must never be dropped unconfirmed
# ---------------------------------------------------------------------------


def test_transport_failure_retains_data(spool: Spool, make_shipper: Callable[..., Shipper]) -> None:
    """The common case during an outage: the server is simply unreachable."""
    spool.set_identity("probe_id", "p1")
    spool.set_identity("token", "t")
    cfg = AgentConfig(server_url="http://127.0.0.1:1")
    shipper = make_shipper(cfg, spool, httpx.Client(timeout=0.1))

    spool.add_samples(_samples(10))
    result = shipper.ship_once(NOW)

    assert not result.ok
    assert "transport" in (result.error or "")
    assert spool.pending_count() == 10, "unconfirmed data was dropped"
    assert spool.unclaimed_count() == 10, "failed batch must be requeued for retry"


def test_auth_rejection_is_fatal_not_retried(shipper: Shipper, spool: Spool) -> None:
    """Retrying with credentials the server rejects cannot succeed.

    Marked fatal so the agent re-registers instead of looping against a definite no.
    """
    spool.set_identity("probe_id", "unknown-probe")
    spool.set_identity("token", "bogus")
    shipper._probe_id = "unknown-probe"
    shipper._token = "bogus"

    spool.add_samples(_samples(5))
    result = shipper.ship_once(NOW)

    assert not result.ok
    assert result.fatal
    assert spool.pending_count() == 5, "data retained despite auth failure"


def test_duplicate_response_still_clears_spool(shipper: Shipper, spool: Spool) -> None:
    """A duplicate means the server already has the data.

    Treating it as undelivered would keep the rows spooled forever and grow the
    database without bound -- the agent needs permission to forget.
    """
    shipper.register(ProbeInfo(name="p"))
    spool.add_samples(_samples(5))

    first = shipper.ship_once(NOW)
    assert first.ok

    # Re-spool the same measurements and force the same batch_id, as a retry after an
    # ambiguous timeout would.
    spool.add_samples(_samples(5))
    batch = spool.claim_batch(first_batch := "forced-duplicate", limit=100)
    assert len(batch.samples) == 5
    spool.release_batch(first_batch)

    second = shipper.ship_once(NOW)
    assert second.ok
    assert spool.pending_count() == 0


def test_recovery_after_partition_drains_everything(
    server: LiveServer, spool: Spool, make_shipper: Callable[..., Shipper]
) -> None:
    """End-to-end partition and heal: nothing lost, nothing duplicated.

    This is the chaos scenario the design exists for, at unit scale.
    """
    online = AgentConfig(server_url=server.url, ship_batch_size=100)

    registrar = make_shipper(online, spool)
    registrar.register(ProbeInfo(name="p"))

    # --- partitioned: measurement continues, shipping fails ---
    offline = AgentConfig(server_url="http://127.0.0.1:1", ship_batch_size=100)
    dead = make_shipper(offline, spool, httpx.Client(timeout=0.1))

    for hour in range(3):
        spool.add_samples(_samples(200, start=NOW + hour * 3_600_000, ok=False))
        assert not dead.ship_once(NOW).ok

    assert spool.pending_count() == 600, "buffered data lost during partition"

    # --- healed ---
    alive = make_shipper(online, spool)
    for _ in range(20):
        if spool.pending_count() == 0:
            break
        assert alive.ship_once(NOW).ok

    assert spool.pending_count() == 0

    row = server.db().execute("SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM samples").fetchone()
    assert row["n"] == 600, "sample count changed across the partition"
    assert row["oldest"] == NOW, "oldest timestamp altered"


# ---------------------------------------------------------------------------
# Backoff
# ---------------------------------------------------------------------------


def test_backoff_grows_then_caps(spool: Spool, make_shipper: Callable[..., Shipper]) -> None:
    """Backoff must rise during a long outage but stay bounded.

    Too low and a disconnected probe hammers a dead server; too high and recovery goes
    unnoticed, turning a short outage into a long hole in the timeline.
    """
    cfg = AgentConfig(retry_base_delay_s=1.0, retry_max_delay_s=300.0)
    shipper = make_shipper(cfg, spool)

    assert shipper.next_delay_s() == cfg.ship_interval_s, "no backoff when healthy"

    delays = []
    for n in range(1, 15):
        shipper._consecutive_failures = n
        delays.append(shipper.next_delay_s())

    assert delays[0] < delays[3] < delays[6], "backoff should grow"
    assert all(d <= cfg.retry_max_delay_s for d in delays), "backoff exceeded its cap"


def test_backoff_is_jittered(spool: Spool, make_shipper: Callable[..., Shipper]) -> None:
    """Without jitter, probes that fail together retry together.

    They would then hit the network in a synchronized burst the instant connectivity
    returns -- exactly when it is least able to absorb one.
    """
    shipper = make_shipper(AgentConfig(), spool)
    shipper._consecutive_failures = 5

    delays = {shipper.next_delay_s() for _ in range(20)}
    assert len(delays) > 1, "delays are identical; jitter is not being applied"


def test_success_resets_backoff(shipper: Shipper, spool: Spool) -> None:
    shipper.register(ProbeInfo(name="p"))
    shipper._consecutive_failures = 5

    spool.add_samples(_samples(3))
    assert shipper.ship_once(NOW).ok

    assert shipper.consecutive_failures == 0
