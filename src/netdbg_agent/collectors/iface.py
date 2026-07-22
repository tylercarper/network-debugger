"""Network interface collector.

Reads link state and error counters via psutil, which -- unlike routes -- it does expose
cross-platform. The value here is in the *deltas*: a rising error or drop count is a
physical-layer problem (a failing cable, RF interference, a dying port) that ICMP loss
alone cannot distinguish from an upstream outage.

Cumulative counters are stored and differenced server-side rather than here, for the same
reason individual pings are shipped rather than a loss percentage: a raw counter can
always be differenced later, but a difference computed against the wrong baseline -- for
instance across a counter reset on link bounce -- cannot be undone.
"""

from __future__ import annotations

from dataclasses import dataclass

import psutil

from netdbg_common.enums import SampleKind
from netdbg_common.models import Sample

__all__ = ["InterfaceStats", "read_interface", "sample_interface"]


@dataclass(frozen=True, slots=True)
class InterfaceStats:
    is_up: bool
    speed_mbps: int
    mtu: int
    rx_errors: int
    tx_errors: int
    rx_drops: int
    tx_drops: int


def read_interface(name: str) -> InterfaceStats | None:
    """Read one interface's state and counters.

    Returns None when the interface does not exist -- which is itself meaningful, e.g. a
    USB adapter that fell off the bus. The caller records that as a distinct sample
    rather than an error.
    """
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)

    if name not in stats or name not in counters:
        return None

    s = stats[name]
    c = counters[name]
    return InterfaceStats(
        is_up=s.isup,
        speed_mbps=s.speed,
        mtu=s.mtu,
        rx_errors=c.errin,
        tx_errors=c.errout,
        rx_drops=c.dropin,
        tx_drops=c.dropout,
    )


def sample_interface(name: str, ts: int, *, seq: int | None = None) -> Sample:
    """Sample interface health. Always returns a Sample, never raises.

    ``success`` reflects link state: down is a failure, up is a success. The cumulative
    error and drop counters ride in ``value_ms`` as a single packed total -- the server
    differences consecutive samples to recover the per-interval error rate.

    Packing several counters into one field is a deliberate compromise: the hot ``samples``
    table is kept narrow (it takes millions of rows a day), and the exact split between
    rx/tx errors and drops matters far less than *that errors are climbing at all*. A
    dedicated wide table can come later if the breakdown proves diagnostic.
    """
    stats = read_interface(name)

    if stats is None:
        # Interface absent: the adapter is gone. Recorded as a failure with a sentinel so
        # it is distinguishable from a present-but-down link.
        return Sample(
            ts=ts,
            kind=SampleKind.IFACE,
            target=name,
            success=False,
            code=-1,
            seq=seq,
        )

    error_total = stats.rx_errors + stats.tx_errors + stats.rx_drops + stats.tx_drops
    return Sample(
        ts=ts,
        kind=SampleKind.IFACE,
        target=name,
        success=stats.is_up,
        value_ms=float(error_total),
        # code carries link speed, a cheap way to catch a gigabit link that renegotiated
        # down to 100Mb -- a classic symptom of a marginal cable.
        code=stats.speed_mbps,
        seq=seq,
    )
