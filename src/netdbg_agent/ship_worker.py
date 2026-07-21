"""Background shipping thread.

Shipping must never block collection. When a server is merely unreachable the failure
returns in microseconds, but when packets are **blackholed** -- no route, no RST -- a TCP
connect hangs until its timeout. A router that has stopped forwarding blackholes packets;
it does not send RSTs. So the blocking case is not the exotic one, it is what a real
outage looks like.

Running shipping inline therefore stalls measurement during precisely the window the
probe exists to observe, and the resulting gap is invisible in the data: it is
indistinguishable from the probe having been switched off.

The spool is already the handoff point between the two loops, so they need no other
coordination -- collection writes, this thread drains.
"""

from __future__ import annotations

import logging
import threading

from netdbg_agent.config import AgentConfig
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool
from netdbg_common.models import ProbeInfo
from netdbg_common.timeutil import MonotonicClock

__all__ = ["ShipWorker"]

log = logging.getLogger("netdbg.agent.ship")


class ShipWorker:
    """Drains the spool on a background thread."""

    def __init__(
        self,
        config: AgentConfig,
        spool: Spool,
        shipper: Shipper,
        probe_info: ProbeInfo,
        clock: MonotonicClock | None = None,
    ) -> None:
        self._cfg = config
        self._spool = spool
        self._shipper = shipper
        self._probe_info = probe_info
        self._clock = clock or MonotonicClock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._last_error: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        # Daemon so a hung network call can never prevent process exit -- the spool is
        # durable, so anything in flight is safe to abandon and re-send next start.
        self._thread = threading.Thread(target=self._run, name="netdbg-ship", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def cycles(self) -> int:
        return self._cycles

    @property
    def last_error(self) -> str | None:
        return self._last_error

    # -- loop --------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            delay = self._cfg.ship_interval_s
            try:
                delay = self.ship_once()
            except Exception:
                # A shipping bug must never kill the thread; collection continues
                # regardless, but a dead shipper would silently stop draining.
                log.exception("ship cycle failed")
            self._cycles += 1

            # Event.wait rather than sleep, so stop() is responsive during a long
            # backoff instead of waiting out the full delay.
            self._stop.wait(delay)

    def ship_once(self) -> float:
        """One registration-and-ship attempt. Returns the delay before the next.

        Exposed separately from the loop so tests can drive it deterministically
        without threading.
        """
        if not self._shipper.is_registered and not self._shipper.register(self._probe_info):
            self._last_error = "registration failed"
            return self._shipper.next_delay_s()

        result = self._shipper.ship_once(self._clock.now_ms())

        if result.fatal:
            # Credentials or protocol are wrong; only re-registration can help.
            log.warning("fatal ship error, will re-register: %s", result.error)
            self._shipper.clear_identity()

        self._last_error = result.error
        return self._shipper.next_delay_s()
