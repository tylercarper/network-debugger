"""Default gateway discovery.

There is **no maintained cross-platform library for this.** ``netifaces`` is archived
with no wheels for modern Python, and ``psutil`` -- despite widespread belief -- has no
route API at all, only interface addresses. So this is a small per-platform parser.

Parsing is kept strictly separate from execution: the ``parse_*`` functions are pure and
take text, so every one of them is testable on any machine against committed fixtures.
The platform functions do nothing but run a command and hand its output to a parser.

Where a JSON output mode exists it is used, because text output is localized and its
column layout varies between versions.
"""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import subprocess
from dataclasses import dataclass

__all__ = [
    "Gateway",
    "discover_gateway",
    "parse_linux_ip_route",
    "parse_macos_route",
    "parse_windows_get_netroute",
]

_TIMEOUT_S = 5.0


@dataclass(frozen=True, slots=True)
class Gateway:
    address: str
    interface: str | None = None


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------

_MACOS_GATEWAY = re.compile(r"^\s*gateway:\s*(\S+)", re.MULTILINE)
_MACOS_INTERFACE = re.compile(r"^\s*interface:\s*(\S+)", re.MULTILINE)


def parse_macos_route(output: str) -> Gateway | None:
    """Parse ``route -n get default``.

    Returns None rather than raising on unrecognised input: a probe with no default
    route is a real state -- an unplugged cable, an interface still coming up -- and
    losing all other measurements to an exception would be a poor trade.
    """
    match = _MACOS_GATEWAY.search(output)
    if match is None:
        return None

    address = match.group(1)
    # A link-local default (`gateway: link#N`) means no usable next-hop address.
    if not _looks_like_ip(address):
        return None

    iface = _MACOS_INTERFACE.search(output)
    return Gateway(address=address, interface=iface.group(1) if iface else None)


def parse_linux_ip_route(output: str) -> Gateway | None:
    """Parse ``ip -j route show default``.

    The ``-j`` JSON mode is used deliberately: the text form is locale-dependent and its
    field order has changed across iproute2 versions.
    """
    try:
        routes = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(routes, list):
        return None

    for route in routes:
        if not isinstance(route, dict):
            continue
        gw = route.get("gateway")
        if isinstance(gw, str) and _looks_like_ip(gw):
            dev = route.get("dev")
            return Gateway(address=gw, interface=dev if isinstance(dev, str) else None)

    return None


def parse_windows_get_netroute(output: str) -> Gateway | None:
    """Parse ``Get-NetRoute -DestinationPrefix 0.0.0.0/0 | ConvertTo-Json``.

    PowerShell emits a bare object rather than a list when exactly one route matches,
    so both shapes are handled.

    ``route print`` is deliberately avoided: its output is localized and column-aligned,
    which makes it fragile to parse on any non-English Windows install.
    """
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        return None

    routes = data if isinstance(data, list) else [data]

    best: Gateway | None = None
    best_metric: int | None = None

    for route in routes:
        if not isinstance(route, dict):
            continue
        gw = route.get("NextHop")
        if not isinstance(gw, str) or not _looks_like_ip(gw):
            continue
        # 0.0.0.0 as next hop means an on-link route, not a gateway.
        if gw in ("0.0.0.0", "::"):
            continue

        metric = route.get("RouteMetric")
        metric_val = metric if isinstance(metric, int) else 9999
        if best_metric is None or metric_val < best_metric:
            iface = route.get("InterfaceAlias")
            best = Gateway(address=gw, interface=iface if isinstance(iface, str) else None)
            best_metric = metric_val

    return best


def _looks_like_ip(value: str) -> bool:
    """Cheap sanity check that a parsed token is an address, not a keyword.

    Catches things like macOS's ``link#12`` and PowerShell's empty-string next hops.
    Uses the stdlib rather than a hand-rolled regex, which gets IPv6 subtly wrong.
    """
    # Strip an IPv6 zone identifier ("fe80::1%en0") -- ipaddress rejects it, but a
    # link-local default route on macOS is written exactly this way and is valid.
    addr = value.split("%", 1)[0]
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Platform execution
# ---------------------------------------------------------------------------


def _run(cmd: list[str]) -> str | None:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT_S, check=False
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    return result.stdout if result.returncode == 0 else None


def discover_gateway(system: str | None = None) -> Gateway | None:
    """Find the default gateway for this host.

    Returns None when there is no default route or the platform command is unavailable.
    Callers treat that as "gateway unknown" and keep measuring everything else -- the
    absence of a default route is itself diagnostic.
    """
    system = system or platform.system()

    if system == "Darwin":
        output = _run(["route", "-n", "get", "default"])
        return parse_macos_route(output) if output else None

    if system == "Linux":
        output = _run(["ip", "-j", "route", "show", "default"])
        return parse_linux_ip_route(output) if output else None

    if system == "Windows":
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | ConvertTo-Json",
            ]
        )
        return parse_windows_get_netroute(output) if output else None

    return None
