"""Enumerations shared by agent and server.

``SampleKind`` values are persisted as integers in the ``samples`` hot table (see the
storage design: that table carries ~1.7M rows/day, so every column is kept narrow).
**Never renumber an existing member** — stored rows would silently change meaning.
Append new members with new integers instead.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

__all__ = ["EventType", "LinkType", "ProbeStatus", "SampleKind", "Severity"]


class SampleKind(IntEnum):
    """Measurement type. Persisted as an int — see module docstring before editing."""

    ICMP = 1
    DNS = 2
    HTTP = 3
    WIFI = 4
    IFACE = 5
    DHCP = 6


class EventType(StrEnum):
    """Derived events. Stored as text in the (much smaller) ``events`` table."""

    OUTAGE = "outage"
    GATEWAY_UP_INTERNET_DOWN = "gateway_up_internet_down"
    LATENCY_SPIKE = "latency_spike"
    LOSS_BURST = "loss_burst"
    DNS_FAILURE = "dns_failure"
    ROAM = "roam"
    RF_DEGRADATION = "rf_degradation"
    LINK_CHANGE = "link_change"
    ICMP_FILTERED = "icmp_filtered"
    """ICMP fails while HTTP succeeds — routers rate-limit ICMP, so this is the
    low-severity classification that prevents a false ``gateway_up_internet_down``."""

    CLOCK_STEP = "clock_step"
    """Wall-clock discontinuity. Also covers wake-from-sleep, which would otherwise
    look like a flawless outage spanning the sleep interval."""

    PROBE_SILENCE = "probe_silence"
    """Server-side only: a probe stopped reporting. Cannot be self-reported by
    definition. If the probe later backfills clean local samples, that proves the
    probe->server path broke rather than the probe's own connectivity."""


class Severity(StrEnum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


class LinkType(StrEnum):
    WIRED = "wired"
    WIFI = "wifi"
    UNKNOWN = "unknown"


class ProbeStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    RETIRED = "retired"
