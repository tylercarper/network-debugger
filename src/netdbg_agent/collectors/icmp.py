"""ICMP collector.

Uses ``icmplib`` with ``privileged=True`` uniformly on every platform. Admin/root is
available on all probe machines, which removes what would otherwise be the most fragile
code in the project: a hand-rolled ``IcmpSendEcho2`` ctypes binding for Windows, where
``icmplib``'s unprivileged mode is unsupported. Raw-socket ICMP behaves identically
across macOS, Linux, and Windows.

**Individual results are shipped, never agent-side aggregates.** A loss percentage can
always be recomputed server-side from individual pings; the individual pings cannot be
recovered from a percentage. This also means a single dropped packet stays visible
rather than being averaged into insignificance.
"""

from __future__ import annotations

from dataclasses import dataclass

from icmplib import ICMPLibError, ping

from netdbg_common.enums import SampleKind
from netdbg_common.models import Sample

__all__ = ["IcmpTarget", "ping_target"]


@dataclass(frozen=True, slots=True)
class IcmpTarget:
    """A host to ping, with the label its samples are recorded under."""

    address: str
    label: str
    """Stable identity for this target, independent of its address.

    The gateway's IP can change -- a router reboot handing out a different subnet, or a
    replaced router -- but its *role* in the diagnosis does not. Recording samples under
    'gateway' rather than the literal IP keeps a probe's history continuous across such
    a change, which matters because a gateway IP change is itself an event worth
    correlating against.
    """


def ping_target(
    target: IcmpTarget,
    ts: int,
    *,
    timeout_s: float = 1.0,
    seq: int | None = None,
    interval_slip_ms: int | None = None,
) -> Sample:
    """Send one ICMP echo and return the result as a Sample.

    Always returns a Sample, never raises. A failed ping is a *measurement*, not an
    error: failures are the entire point of this system, and an exception escaping here
    would drop the very data an outage produces.

    ``ts`` is passed in rather than read here so that the caller stamps it from the
    monotonic-anchored clock at the moment of measurement.
    """
    try:
        host = ping(
            target.address,
            count=1,
            timeout=timeout_s,
            privileged=True,
            # icmplib defaults to the process id; being explicit keeps concurrent
            # probes on one host from colliding on echo identifiers.
            id=None,
        )
    except ICMPLibError as exc:
        # Name resolution failure, permission denied, unreachable network. All are
        # recorded as a failed measurement with the reason preserved in `code`.
        return Sample(
            ts=ts,
            kind=SampleKind.ICMP,
            target=target.label,
            success=False,
            code=_error_code(exc),
            seq=seq,
            interval_slip_ms=interval_slip_ms,
        )
    except OSError as exc:
        return Sample(
            ts=ts,
            kind=SampleKind.ICMP,
            target=target.label,
            success=False,
            code=exc.errno,
            seq=seq,
            interval_slip_ms=interval_slip_ms,
        )

    # is_alive is False when the packet was sent but no reply arrived -- ordinary loss.
    if not host.is_alive or not host.rtts:
        return Sample(
            ts=ts,
            kind=SampleKind.ICMP,
            target=target.label,
            success=False,
            seq=seq,
            interval_slip_ms=interval_slip_ms,
        )

    return Sample(
        ts=ts,
        kind=SampleKind.ICMP,
        target=target.label,
        success=True,
        value_ms=host.rtts[0],
        seq=seq,
        interval_slip_ms=interval_slip_ms,
    )


def _error_code(exc: ICMPLibError) -> int | None:
    """Map an icmplib exception to a small stable code stored alongside the sample.

    Distinguishing "we could not send" from "nothing replied" matters: the former is a
    local problem with the probe, the latter is a finding about the network.
    """
    name = type(exc).__name__
    return {
        "NameLookupError": 1,
        "SocketPermissionError": 2,
        "SocketAddressError": 3,
        "ICMPSocketError": 4,
        "DestinationUnreachable": 5,
        "TimeExceeded": 6,
    }.get(name)
