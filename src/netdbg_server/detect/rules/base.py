"""Detection rule interface.

A rule is a pure function of a :class:`ProbeWindow` to a list of :class:`DetectedEvent`.
Purity is the whole point: it makes rules testable against synthetic sample sequences
with no database, and re-runnable over any historical window to retroactively improve
events from data already stored.

Two conventions every rule follows:

* **Hysteresis, not a single sample.** A rule requires N consecutive samples to enter a
  state and N to leave it. A one-sample blip must not open and close an event, or a
  marginal link would produce a storm of them and the user would stop trusting the tool.

* **Evidence, always.** Each event carries the values that triggered it, so a human or an
  agent can audit the detection rather than trust it. An event with no evidence is a
  claim with no receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from netdbg_common.enums import EventType, Severity
from netdbg_server.detect.window import ProbeWindow

__all__ = ["DetectedEvent", "Rule"]


@dataclass(slots=True)
class DetectedEvent:
    """A rule's output, before it is persisted.

    ``ended_ts`` of None means the event was still ongoing at the edge of the window --
    not that it has no duration. The engine re-runs continuously, so an ongoing event is
    updated in place (via the ``(probe_id, event_type, started_ts)`` upsert key) once its
    end is observed in a later window.
    """

    event_type: EventType
    severity: Severity
    confidence: float
    started_ts: int
    ended_ts: int | None = None
    subtype: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)


class Rule(Protocol):
    """A detection rule.

    ``detector_version`` is stored on every event the rule emits, so that when a rule is
    improved, events from the old version can be found and re-derived rather than being
    silently mixed with new ones.
    """

    name: str
    detector_version: int

    def detect(self, window: ProbeWindow) -> list[DetectedEvent]: ...
