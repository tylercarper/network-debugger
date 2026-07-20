"""Shared wire models, enums, and time handling for the netdbg agent and server."""

from netdbg_common.enums import EventType, LinkType, ProbeStatus, SampleKind, Severity
from netdbg_common.models import (
    PROTOCOL_VERSION,
    Batch,
    Event,
    IngestResponse,
    ProbeInfo,
    RegisterRequest,
    RegisterResponse,
    Sample,
    WifiSample,
)
from netdbg_common.timeutil import ClockStep, MonotonicClock, utc_now_ms

__all__ = [
    "PROTOCOL_VERSION",
    "Batch",
    "ClockStep",
    "Event",
    "EventType",
    "IngestResponse",
    "LinkType",
    "MonotonicClock",
    "ProbeInfo",
    "ProbeStatus",
    "RegisterRequest",
    "RegisterResponse",
    "Sample",
    "SampleKind",
    "Severity",
    "WifiSample",
    "utc_now_ms",
]
