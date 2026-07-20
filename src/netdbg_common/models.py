"""Wire models shared by agent and server.

These types are the coupling point between the two halves of the system, which is why
they live in a package both import rather than being defined twice. Every batch carries
:data:`PROTOCOL_VERSION` so the server can flag agent/server skew explicitly instead of
silently dropping fields it does not recognise.

Timestamp discipline (the rule the whole design depends on): ``ts`` is stamped by the
agent at the moment of measurement, in UTC epoch milliseconds, and is **immutable
end to end**. The server records its own ``recv_ts`` separately and never overrides
``ts``. Nothing anywhere infers measurement time from arrival time — samples routinely
arrive hours late, precisely because an outage is when the server is unreachable.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from netdbg_common.enums import EventType, LinkType, SampleKind, Severity

__all__ = [
    "PROTOCOL_VERSION",
    "Batch",
    "Event",
    "IngestResponse",
    "ProbeInfo",
    "RegisterRequest",
    "RegisterResponse",
    "Sample",
    "WifiSample",
]

PROTOCOL_VERSION = 1


class _Wire(BaseModel):
    """Base for wire types: reject unknown fields so version skew surfaces loudly."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Sample(_Wire):
    """One individual measurement.

    Deliberately narrow, and deliberately *not* aggregated: the agent ships every
    individual ping result rather than a loss percentage. Aggregates can always be
    recomputed server-side, but detail that was never sent cannot be recovered.
    """

    ts: int = Field(description="UTC epoch ms at measurement. Immutable end to end.")
    kind: SampleKind
    target: str = Field(description="Address or label; server maps to a targets row id.")
    success: bool
    value_ms: float | None = Field(
        default=None, description="RTT / resolve time / elapsed. None when failed."
    )
    code: int | None = Field(default=None, description="HTTP status, DNS rcode, or errno.")
    seq: int | None = None

    interval_slip_ms: int | None = Field(
        default=None,
        description=(
            "How far this sample's actual interval exceeded its scheduled one. A busy "
            "host delays the sampling loop, and delayed samples otherwise look like "
            "failures; detection excludes samples whose slip exceeds a threshold."
        ),
    )
    ntp_synced: bool | None = Field(
        default=None,
        description="Host clock sync state; correlation confidence degrades when false.",
    )


class WifiSample(_Wire):
    """WiFi radio telemetry.

    Identity fields (``ssid``/``bssid``) are optional by design, not by oversight: every
    platform gates them behind a permission while leaving radio metrics freely readable.
    macOS in particular exposes no BSSID at all via the supported path. ``degraded_fields``
    records what this platform could not provide, so the dashboard can distinguish
    "unavailable here" from "missing data" — and so roam detection knows to fall back to
    channel/RSSI discontinuity where BSSID is absent.
    """

    ts: int
    ssid: str | None = None
    bssid: str | None = None
    rssi_dbm: int | None = None
    noise_dbm: int | None = None
    snr_db: int | None = None
    channel: int | None = None
    band: str | None = Field(default=None, description="'2.4GHz' | '5GHz' | '6GHz'")
    width_mhz: int | None = None
    tx_rate_mbps: float | None = None
    rx_rate_mbps: float | None = None
    mcs: int | None = None
    nss: int | None = None
    tx_retries: int | None = None
    tx_failed: int | None = None
    beacon_loss: int | None = None
    source: str = Field(description="'iw' | 'system_profiler' | 'corewlan' | 'wlanapi' | 'fake'")
    degraded_fields: list[str] = Field(
        default_factory=list, description="Fields unavailable on this platform/permission state."
    )


class Event(_Wire):
    """A derived event.

    Agents emit only events they alone can observe (``clock_step``); everything else is
    derived server-side, where detection can be re-run idempotently over stored samples.
    """

    event_type: EventType
    subtype: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    started_ts: int
    ended_ts: int | None = Field(default=None, description="None means still ongoing.")
    evidence: dict[str, object] = Field(
        default_factory=dict,
        description="Triggering values, so a detection can be audited rather than trusted.",
    )


class ProbeInfo(_Wire):
    """Probe self-description, sent at registration."""

    name: str
    link_type: LinkType = LinkType.UNKNOWN
    os_name: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    capabilities: list[str] = Field(
        default_factory=list,
        description="e.g. ['wifi.bssid', 'icmp.privileged'] — drives graceful degradation.",
    )


class Batch(_Wire):
    """A shipment of buffered measurements.

    ``batch_id`` makes ingest idempotent. Duplicate delivery is the *normal* case here,
    not an edge case: the agent retries across a flapping network and cannot know whether
    a request that timed out was actually applied.
    """

    protocol_version: int = PROTOCOL_VERSION
    probe_id: str
    batch_id: str = Field(description="UUID; server treats a repeat as a no-op.")
    agent_ts: int = Field(description="Agent clock at send time; used to estimate skew.")
    samples: list[Sample] = Field(default_factory=list)
    wifi_samples: list[WifiSample] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)


class IngestResponse(_Wire):
    accepted: int
    duplicate: bool = Field(description="True when this batch_id was already applied.")
    server_ts: int
    clock_offset_ms: int = Field(
        description="Estimated agent-vs-server skew. Recorded, never used to rewrite ts."
    )
    config_revision: int = Field(
        description="Agent refetches config only when this changes — avoids a control plane."
    )


class RegisterRequest(_Wire):
    probe: ProbeInfo
    probe_id: str | None = Field(default=None, description="Echoed back on re-registration.")


class RegisterResponse(_Wire):
    probe_id: str
    token: str
    config_revision: int
