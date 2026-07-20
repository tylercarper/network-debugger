"""Gateway parser tests.

Fixtures are captured from real commands and then sanitized -- the repo is public, and a
real gateway address plus a BSSID is enough to locate a house. Every parser must return
None rather than raise on unparseable input: a probe with no default route is a real
state, and losing all other measurements to an exception would be a poor trade.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netdbg_agent.collectors.gateway import (
    Gateway,
    parse_linux_ip_route,
    parse_macos_route,
    parse_windows_get_netroute,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "route"


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------


def test_macos_parses_real_output() -> None:
    """Against output captured from an actual `route -n get default`."""
    gw = parse_macos_route((FIXTURES / "macos_route_default.txt").read_text())

    assert gw == Gateway(address="192.168.1.1", interface="en0")


def test_macos_no_route() -> None:
    """`route` prints this when nothing is connected."""
    output = "   route to: default\nroute: writing to routing socket: not in table"
    assert parse_macos_route(output) is None


def test_macos_link_local_gateway_rejected() -> None:
    """A `link#N` gateway is a directly-attached route with no next-hop address.

    Pinging the literal string 'link#12' would fail on every cycle and look like a
    permanent gateway outage.
    """
    output = "   route to: default\n    gateway: link#12\n  interface: utun4\n"
    assert parse_macos_route(output) is None


def test_macos_ipv6_gateway() -> None:
    output = "   route to: default\n    gateway: fe80::1%en0\n  interface: en0\n"
    gw = parse_macos_route(output)
    assert gw is not None
    assert gw.address.startswith("fe80::")


@pytest.mark.parametrize("text", ["", "garbage", "gateway:", "\n\n\n"])
def test_macos_malformed_returns_none(text: str) -> None:
    assert parse_macos_route(text) is None


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------


def test_linux_parses_real_docker_output() -> None:
    """Against output captured from `ip -j route show default` in a container."""
    gw = parse_linux_ip_route((FIXTURES / "linux_ip_route_default.json").read_text())

    assert gw == Gateway(address="172.17.0.1", interface="eth0")


def test_linux_empty_route_table() -> None:
    """`ip -j` emits an empty array when there is no default route."""
    assert parse_linux_ip_route("[]") is None


def test_linux_multiple_defaults_takes_first_with_gateway() -> None:
    """Multi-homed hosts list several defaults; the first usable one wins."""
    output = """[
      {"dst":"default","dev":"tun0","flags":[]},
      {"dst":"default","gateway":"10.0.0.1","dev":"eth0","flags":[]}
    ]"""
    gw = parse_linux_ip_route(output)
    assert gw is not None
    assert gw.address == "10.0.0.1"


@pytest.mark.parametrize("text", ["", "not json", "{}", "null", '{"gateway":"x"}'])
def test_linux_malformed_returns_none(text: str) -> None:
    assert parse_linux_ip_route(text) is None


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def test_windows_single_route_is_a_bare_object() -> None:
    """PowerShell emits an object, not a list, when exactly one route matches.

    Assuming a list here would break on the single-NIC case -- i.e. most desktops.
    """
    output = """{
      "DestinationPrefix": "0.0.0.0/0",
      "NextHop": "192.168.1.1",
      "InterfaceAlias": "Ethernet",
      "RouteMetric": 0
    }"""
    gw = parse_windows_get_netroute(output)

    assert gw == Gateway(address="192.168.1.1", interface="Ethernet")


def test_windows_multiple_routes_picks_lowest_metric() -> None:
    """A laptop on both wifi and ethernet has two defaults; metric decides.

    Picking the wrong one would measure a path the traffic is not taking.
    """
    output = """[
      {"NextHop":"192.168.1.1","InterfaceAlias":"Wi-Fi","RouteMetric":50},
      {"NextHop":"10.0.0.1","InterfaceAlias":"Ethernet","RouteMetric":10}
    ]"""
    gw = parse_windows_get_netroute(output)

    assert gw is not None
    assert gw.address == "10.0.0.1", "should prefer the lower-metric route"


def test_windows_onlink_nexthop_rejected() -> None:
    """0.0.0.0 as next hop means on-link, not a gateway."""
    output = '{"NextHop":"0.0.0.0","InterfaceAlias":"Ethernet","RouteMetric":0}'
    assert parse_windows_get_netroute(output) is None


@pytest.mark.parametrize("text", ["", "not json", "[]", "null"])
def test_windows_malformed_returns_none(text: str) -> None:
    assert parse_windows_get_netroute(text) is None


# ---------------------------------------------------------------------------
# Cross-platform invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parser",
    [parse_macos_route, parse_linux_ip_route, parse_windows_get_netroute],
)
@pytest.mark.parametrize(
    "text",
    ["", "\x00\x01binary", "a" * 10_000, "{'almost': 'json'}", "<html>captive portal</html>"],
)
def test_no_parser_ever_raises(parser: object, text: str) -> None:
    """A parser crash would take the whole agent down with it.

    Malformed output is plausible in the field: a truncated pipe, a localized error
    message, a captive portal intercepting something. None of it may raise.
    """
    assert parser(text) is None  # type: ignore[operator]
