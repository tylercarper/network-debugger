"""Tests for the shared wire models.

Focused on the properties that protect data integrity across the agent/server boundary:
timestamp immutability through serialisation, and loud failure on version skew.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netdbg_common.enums import EventType, SampleKind, Severity
from netdbg_common.models import PROTOCOL_VERSION, Batch, Event, Sample, WifiSample


def test_sample_roundtrips_timestamp_exactly() -> None:
    """``ts`` must survive serialisation byte-for-byte.

    Samples routinely sit in the spool for hours before shipping. Any float coercion or
    precision loss in transit would silently shift measurements in the timeline.
    """
    original = Sample(
        ts=1_700_000_000_123, kind=SampleKind.ICMP, target="1.1.1.1", success=True, value_ms=12.5
    )
    restored = Sample.model_validate_json(original.model_dump_json())

    assert restored.ts == 1_700_000_000_123
    assert isinstance(restored.ts, int)
    assert restored == original


def test_batch_roundtrips_with_old_timestamps() -> None:
    """Backfilled batches carry timestamps hours old; nothing may reject or rewrite them."""
    old_ts = 1_700_000_000_000
    batch = Batch(
        probe_id="probe-a",
        batch_id="b-1",
        agent_ts=old_ts + 6 * 3_600_000,
        samples=[
            Sample(ts=old_ts + i, kind=SampleKind.ICMP, target="gw", success=False)
            for i in range(3)
        ],
    )
    restored = Batch.model_validate_json(batch.model_dump_json())

    assert [s.ts for s in restored.samples] == [old_ts, old_ts + 1, old_ts + 2]
    assert restored.protocol_version == PROTOCOL_VERSION


def test_unknown_field_is_rejected() -> None:
    """Version skew must surface loudly rather than silently dropping data."""
    with pytest.raises(ValidationError):
        Sample.model_validate(
            {
                "ts": 1,
                "kind": SampleKind.ICMP,
                "target": "gw",
                "success": True,
                "unexpected_field": "from a newer agent",
            }
        )


def test_samples_are_immutable() -> None:
    """Frozen models prevent anything downstream from rewriting a measurement time."""
    sample = Sample(ts=1_700_000_000_000, kind=SampleKind.ICMP, target="gw", success=True)
    with pytest.raises(ValidationError):
        sample.ts = 0


def test_failed_sample_has_no_value() -> None:
    sample = Sample(ts=1, kind=SampleKind.ICMP, target="1.1.1.1", success=False)
    assert sample.value_ms is None


def test_wifi_sample_degrades_without_identity_fields() -> None:
    """The macOS case: radio metrics present, BSSID structurally unavailable.

    This must be representable without error, and must record *why* the field is empty
    so the dashboard can show 'unavailable here' rather than implying missing data.
    """
    sample = WifiSample(
        ts=1_700_000_000_000,
        ssid="HomeNet",
        bssid=None,
        rssi_dbm=-61,
        noise_dbm=-88,
        snr_db=27,
        channel=149,
        band="5GHz",
        width_mhz=80,
        source="system_profiler",
        degraded_fields=["bssid"],
    )
    assert sample.bssid is None
    assert "bssid" in sample.degraded_fields


def test_event_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Event(
            event_type=EventType.OUTAGE,
            severity=Severity.CRITICAL,
            confidence=1.5,
            started_ts=1,
        )


def test_ongoing_event_has_no_end() -> None:
    event = Event(
        event_type=EventType.GATEWAY_UP_INTERNET_DOWN,
        severity=Severity.CRITICAL,
        confidence=0.9,
        started_ts=1_700_000_000_000,
        evidence={"gateway_success_rate": 1.0, "anchor_success_rate": 0.0},
    )
    assert event.ended_ts is None
    assert event.evidence["anchor_success_rate"] == 0.0


def test_sample_kind_values_are_stable() -> None:
    """These ints are persisted in the hot table; renumbering silently corrupts history."""
    assert (SampleKind.ICMP, SampleKind.DNS, SampleKind.HTTP) == (1, 2, 3)
    assert (SampleKind.WIFI, SampleKind.IFACE, SampleKind.DHCP) == (4, 5, 6)
