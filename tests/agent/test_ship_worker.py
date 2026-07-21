"""Background shipping thread.

The regression this file exists for (#27): shipping must never block collection.

When a server merely refuses connections the failure returns in microseconds. When
packets are **blackholed** -- no route, no RST -- a TCP connect hangs until timeout. A
router that has stopped forwarding blackholes packets; it does not send RSTs, so the
blocking case is what a real outage looks like, not an exotic one.

Running shipping inline stalled measurement for the full connect timeout, which meant
the probe went partially blind during exactly the window it exists to observe. Worse,
the resulting gap is invisible: it is indistinguishable from the probe being switched
off.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from netdbg_agent.collectors.icmp import IcmpTarget
from netdbg_agent.config import AgentConfig
from netdbg_agent.runner import AgentRunner
from netdbg_agent.ship_worker import ShipWorker
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_common.models import ProbeInfo

# TEST-NET-3. Routable-looking but blackholed, so a connect hangs rather than being
# refused -- which is what reproduces the original bug.
BLACKHOLE_URL = "http://203.0.113.1:8080"

# Nothing listening on localhost:1, so connects are refused immediately.
REFUSED_URL = "http://127.0.0.1:1"


class FakeHost:
    def __init__(self, alive: bool, rtts: list[float]) -> None:
        self.is_alive = alive
        self.rtts = rtts


@pytest.fixture
def spool(tmp_path: Path) -> Iterator[Spool]:
    s = Spool(tmp_path / "spool.db")
    yield s
    s.close()


def _runner(cfg: AgentConfig, spool: Spool) -> AgentRunner:
    return AgentRunner(
        config=cfg,
        spool=spool,
        shipper=Shipper(cfg, spool),
        targets=[IcmpTarget(address="192.0.2.1", label="gateway")],
    )


# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------


def test_collection_is_not_blocked_by_a_blackholed_server(spool: Spool) -> None:
    """The #27 regression, stated as a timing guarantee.

    Ten collection cycles against a blackholed server must complete promptly. Before the
    fix each cycle blocked for the full connect timeout, so this took tens of seconds
    and the probe recorded nothing during that time.
    """
    cfg = AgentConfig(server_url=BLACKHOLE_URL, ship_timeout_s=10.0, ship_interval_s=0.01)
    runner = _runner(cfg, spool)
    shipper = runner.shipper
    shipper._probe_id, shipper._token = "id", "token"  # skip registration

    worker = ShipWorker(cfg, spool, shipper, ProbeInfo(name="p"), clock=runner.clock)
    worker.start()
    try:
        start = time.monotonic()
        with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
            for _ in range(10):
                runner.collect_once()
        elapsed = time.monotonic() - start
    finally:
        worker.stop(timeout=1.0)
        shipper.close()

    assert elapsed < 2.0, (
        f"10 collection cycles took {elapsed:.1f}s against a blackholed server; "
        "shipping is blocking collection again (#27)"
    )
    assert spool.pending_count() == 10, "every cycle must still have been recorded"


def test_measurements_continue_at_full_rate_during_a_stall(spool: Spool) -> None:
    """Cadence, not just completion.

    A probe that collects 10 samples in a burst after a 30s stall is not equivalent to
    one that collected them evenly -- the timeline would show a hole either way.
    """
    cfg = AgentConfig(server_url=BLACKHOLE_URL, ship_timeout_s=10.0, ship_interval_s=0.01)
    runner = _runner(cfg, spool)
    runner.shipper._probe_id, runner.shipper._token = "id", "token"

    worker = ShipWorker(cfg, spool, runner.shipper, ProbeInfo(name="p"), clock=runner.clock)
    worker.start()
    try:
        stamps = []
        with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(False, [])):
            for _ in range(8):
                t0 = time.monotonic()
                runner.collect_once()
                stamps.append(time.monotonic() - t0)
    finally:
        worker.stop(timeout=1.0)
        runner.shipper.close()

    worst = max(stamps)
    assert worst < 0.5, f"a collection cycle took {worst:.2f}s; the network stalled it"


def test_refused_connection_also_does_not_block(spool: Spool) -> None:
    """The easy case, kept as a control.

    If this ever regresses it means something other than connect-hang is at fault.
    """
    cfg = AgentConfig(server_url=REFUSED_URL, ship_interval_s=0.01)
    runner = _runner(cfg, spool)
    runner.shipper._probe_id, runner.shipper._token = "id", "token"

    worker = ShipWorker(cfg, spool, runner.shipper, ProbeInfo(name="p"), clock=runner.clock)
    worker.start()
    try:
        start = time.monotonic()
        with patch("netdbg_agent.collectors.icmp.ping", return_value=FakeHost(True, [1.0])):
            for _ in range(10):
                runner.collect_once()
        elapsed = time.monotonic() - start
    finally:
        worker.stop(timeout=1.0)
        runner.shipper.close()

    assert elapsed < 1.0
    assert spool.pending_count() == 10


# ---------------------------------------------------------------------------
# Worker behaviour
# ---------------------------------------------------------------------------


def test_worker_survives_a_shipping_error(spool: Spool) -> None:
    """A shipping bug must not kill the thread.

    Collection continues regardless, but a dead shipper would silently stop draining
    and the spool would grow until it hit its cap.
    """
    cfg = AgentConfig(server_url=REFUSED_URL, ship_interval_s=0.01)
    shipper = Shipper(cfg, spool)
    worker = ShipWorker(cfg, spool, shipper, ProbeInfo(name="p"))

    with patch.object(shipper, "register", side_effect=RuntimeError("boom")):
        worker.start()
        time.sleep(0.2)
        cycles_during_failure = worker.cycles
        worker.stop(timeout=1.0)

    shipper.close()
    assert cycles_during_failure > 1, "worker died on the first exception"


def test_worker_stops_promptly_during_backoff(spool: Spool) -> None:
    """Shutdown must not wait out a long backoff.

    Uses Event.wait rather than sleep so a probe in a five-minute backoff still exits
    quickly when asked.
    """
    cfg = AgentConfig(server_url=REFUSED_URL, ship_interval_s=300.0, retry_base_delay_s=300.0)
    shipper = Shipper(cfg, spool)
    worker = ShipWorker(cfg, spool, shipper, ProbeInfo(name="p"))
    worker.start()
    time.sleep(0.1)

    start = time.monotonic()
    worker.stop(timeout=5.0)
    elapsed = time.monotonic() - start

    shipper.close()
    assert elapsed < 1.0, f"stop() took {elapsed:.1f}s; it is waiting out the backoff"


def test_worker_is_idempotent_on_start(spool: Spool) -> None:
    cfg = AgentConfig(server_url=REFUSED_URL, ship_interval_s=0.05)
    shipper = Shipper(cfg, spool)
    worker = ShipWorker(cfg, spool, shipper, ProbeInfo(name="p"))

    worker.start()
    worker.start()  # must not spawn a second thread
    time.sleep(0.1)
    worker.stop(timeout=1.0)
    shipper.close()


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_spool_is_safe_across_threads(spool: Spool) -> None:
    """Collection and shipping touch the spool from different threads.

    SQLite connections are thread-bound by default, so moving shipping onto its own
    thread broke every spool access from it. Unit tests missed this because each
    created its spool in the same thread it used -- only the live Docker stack
    exercised the real two-thread arrangement. Hence this test.
    """
    import threading as _threading

    errors: list[BaseException] = []
    stop = _threading.Event()

    def writer() -> None:
        try:
            from netdbg_common.enums import SampleKind
            from netdbg_common.models import Sample

            i = 0
            while not stop.is_set() and i < 200:
                spool.add_samples(
                    [
                        Sample(
                            ts=1_700_000_000_000 + i,
                            kind=SampleKind.ICMP,
                            target="gateway",
                            success=True,
                        )
                    ]
                )
                i += 1
        except BaseException as exc:
            errors.append(exc)

    def drainer() -> None:
        try:
            n = 0
            while not stop.is_set() and n < 200:
                batch = spool.claim_batch(f"b{n}", limit=10)
                if batch.is_empty:
                    spool.pending_count()
                else:
                    spool.confirm_batch(f"b{n}")
                n += 1
        except BaseException as exc:
            errors.append(exc)

    threads = [_threading.Thread(target=writer), _threading.Thread(target=drainer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    stop.set()

    assert not errors, f"concurrent spool access raised: {errors[0]!r}"


def test_no_measurement_is_lost_under_concurrent_drain(spool: Spool) -> None:
    """The invariant that matters: concurrency must not drop measurements.

    A claim/confirm race could delete rows that were never delivered, which would be
    silent and unrecoverable.
    """
    import threading as _threading

    from netdbg_common.enums import SampleKind
    from netdbg_common.models import Sample

    total = 300
    written = _threading.Event()

    def writer() -> None:
        for i in range(total):
            spool.add_samples(
                [
                    Sample(
                        ts=1_700_000_000_000 + i,
                        kind=SampleKind.ICMP,
                        target="gateway",
                        success=True,
                    )
                ]
            )
        written.set()

    claimed: list[int] = []

    def drainer() -> None:
        n = 0
        while not written.is_set() or spool.unclaimed_count() > 0:
            batch = spool.claim_batch(f"d{n}", limit=25)
            if not batch.is_empty:
                claimed.append(len(batch.samples))
                spool.confirm_batch(f"d{n}")
            n += 1
            if n > 1000:
                break

    threads = [_threading.Thread(target=writer), _threading.Thread(target=drainer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert sum(claimed) == total, f"delivered {sum(claimed)} of {total} measurements"
    assert spool.pending_count() == 0
