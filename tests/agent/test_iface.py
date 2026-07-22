"""Interface collector tests.

Link state maps to success, error counters ride along for server-side differencing, and
an absent interface is a distinct, recorded condition rather than a crash.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from netdbg_agent.collectors.iface import read_interface, sample_interface
from netdbg_common.enums import SampleKind

NOW = 1_700_000_000_000


def _stats(isup: bool = True, speed: int = 1000, mtu: int = 1500) -> dict[str, SimpleNamespace]:
    return {"eth0": SimpleNamespace(isup=isup, speed=speed, mtu=mtu, duplex=2)}


def _counters(
    errin: int = 0, errout: int = 0, dropin: int = 0, dropout: int = 0
) -> dict[str, SimpleNamespace]:
    return {
        "eth0": SimpleNamespace(
            errin=errin,
            errout=errout,
            dropin=dropin,
            dropout=dropout,
            bytes_sent=0,
            bytes_recv=0,
            packets_sent=0,
            packets_recv=0,
        )
    }


def test_reads_healthy_interface() -> None:
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats()),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        stats = read_interface("eth0")

    assert stats is not None
    assert stats.is_up
    assert stats.speed_mbps == 1000


def test_missing_interface_returns_none() -> None:
    """A vanished adapter -- e.g. a USB dongle off the bus -- is meaningful, not an error."""
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats()),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        assert read_interface("wlan9") is None


def test_up_interface_is_success() -> None:
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats(isup=True)),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        sample = sample_interface("eth0", NOW)

    assert sample.success
    assert sample.kind == SampleKind.IFACE


def test_down_interface_is_failure() -> None:
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats(isup=False)),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        sample = sample_interface("eth0", NOW)

    assert not sample.success


def test_absent_interface_is_distinct_from_down() -> None:
    """ "Adapter gone" and "adapter present but link down" are different faults."""
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats()),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        absent = sample_interface("wlan9", NOW)

    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats(isup=False)),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        down = sample_interface("eth0", NOW)

    assert not absent.success and not down.success
    assert absent.code != down.code, "absent and down must be distinguishable"


def test_error_counters_are_carried() -> None:
    """The counters are the point: a rising total is a physical-layer problem."""
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats()),
        patch(
            "netdbg_agent.collectors.iface.psutil.net_io_counters",
            return_value=_counters(errin=5, errout=3, dropin=2, dropout=1),
        ),
    ):
        sample = sample_interface("eth0", NOW)

    assert sample.value_ms == 11.0, "packed error+drop total should be 5+3+2+1"


def test_speed_is_recorded() -> None:
    """A gigabit link renegotiated to 100Mb is a classic marginal-cable symptom."""
    with (
        patch("netdbg_agent.collectors.iface.psutil.net_if_stats", return_value=_stats(speed=100)),
        patch("netdbg_agent.collectors.iface.psutil.net_io_counters", return_value=_counters()),
    ):
        sample = sample_interface("eth0", NOW)

    assert sample.code == 100


def test_reads_real_interfaces() -> None:
    """Smoke test against the host's actual interfaces -- psutil really works here."""
    import psutil

    names = list(psutil.net_if_stats().keys())
    assert names, "host should have at least one interface"

    sample = sample_interface(names[0], NOW)
    assert sample.kind == SampleKind.IFACE
    assert sample.target == names[0]
