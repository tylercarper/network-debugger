"""Ships spooled measurements to the server.

The shipper's guiding rule: **never delete data that has not been confirmed delivered.**
Every failure path either leaves rows claimed (for a later retry) or explicitly releases
them. A bug that drops unconfirmed data would be invisible until the moment an outage
needed explaining.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field

import httpx
from pydantic import ValidationError

from netdbg_agent.config import AgentConfig
from netdbg_agent.spool import PendingBatch, Spool
from netdbg_common.models import Batch, IngestResponse, ProbeInfo, RegisterResponse

__all__ = ["ShipResult", "Shipper"]

_IDENTITY_PROBE_ID = "probe_id"
_IDENTITY_TOKEN = "token"


@dataclass(slots=True)
class ShipResult:
    """Outcome of one shipping attempt."""

    shipped: int = 0
    duplicate: bool = False
    ok: bool = False
    error: str | None = None
    config_revision: int | None = None
    clock_offset_ms: int | None = None
    fatal: bool = field(default=False)
    """A failure that retrying cannot fix -- e.g. rejected auth or protocol skew.

    Distinguished from a transient failure because the response differs: a transient
    error means back off and retry, while a fatal one means stop and surface the problem
    rather than looping against a server that will keep saying no.
    """


class Shipper:
    """Registers the probe and delivers spooled batches."""

    def __init__(
        self, config: AgentConfig, spool: Spool, client: httpx.Client | None = None
    ) -> None:
        self._cfg = config
        self._spool = spool
        self._client = client or httpx.Client(timeout=config.ship_timeout_s)
        self._consecutive_failures = 0
        self._probe_id = spool.get_identity(_IDENTITY_PROBE_ID)
        # An empty token is how clear_identity() marks credentials as revoked; treat it
        # as absent rather than as a valid-but-empty token.
        self._token = spool.get_identity(_IDENTITY_TOKEN) or None

    @property
    def probe_id(self) -> str | None:
        return self._probe_id

    @property
    def is_registered(self) -> bool:
        return self._probe_id is not None and self._token is not None

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    # -- registration ------------------------------------------------------

    def register(self, info: ProbeInfo) -> bool:
        """Register with the server, persisting the resulting identity.

        Re-registers with the stored ``probe_id`` when one exists, so a restart resumes
        the same probe's history rather than appearing as a new probe and fragmenting
        its own timeline.

        Failure here is not fatal to the agent: collection continues into the spool and
        registration is retried. A probe brought up during an outage must still record
        what it sees.
        """
        payload: dict[str, object] = {"probe": info.model_dump(mode="json")}
        if self._probe_id is not None:
            payload["probe_id"] = self._probe_id

        try:
            resp = self._client.post(f"{self._cfg.server_url}/api/v1/register", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError:
            return False

        try:
            parsed = RegisterResponse.model_validate(resp.json())
        except (ValidationError, ValueError):
            # Something answered but did not speak our protocol -- a captive portal
            # intercepting the request is the likely culprit, and is itself a finding
            # worth not crashing over.
            return False

        self._probe_id = parsed.probe_id
        self._token = parsed.token
        self._spool.set_identity(_IDENTITY_PROBE_ID, parsed.probe_id)
        self._spool.set_identity(_IDENTITY_TOKEN, parsed.token)
        return True

    def clear_identity(self) -> None:
        """Forget credentials so the next cycle re-registers.

        Used when the server rejects auth: the stored token is definitively no good, so
        retrying with it is pointless. The ``probe_id`` is deliberately kept in the
        spool, so re-registration resumes the same probe's history rather than starting
        a new one.
        """
        self._token = None
        self._spool.set_identity(_IDENTITY_TOKEN, "")

    # -- shipping ----------------------------------------------------------

    def ship_once(self, now_ms: int) -> ShipResult:
        """Claim, send, and confirm one batch.

        Returns immediately when there is nothing to send or the probe is not yet
        registered.
        """
        if not self.is_registered:
            return ShipResult(ok=False, error="not registered")

        batch_id = str(uuid.uuid4())
        pending = self._spool.claim_batch(batch_id, self._cfg.ship_batch_size)

        if pending.is_empty:
            return ShipResult(ok=True, shipped=0)

        result = self._send(pending, now_ms)

        if result.ok:
            # Delete only now, after the server confirmed. A duplicate response also
            # counts as delivered -- the server already has the data, so holding it
            # locally forever would grow the spool without bound.
            self._spool.confirm_batch(batch_id)
            self._consecutive_failures = 0
        else:
            # Release rather than delete: the data has not been confirmed stored
            # anywhere else, so it must remain here.
            self._spool.release_batch(batch_id)
            self._consecutive_failures += 1

        return result

    def _send(self, pending: PendingBatch, now_ms: int) -> ShipResult:
        assert self._probe_id is not None and self._token is not None

        batch = Batch(
            probe_id=self._probe_id,
            batch_id=pending.batch_id,
            agent_ts=now_ms,
            samples=pending.samples,
            wifi_samples=pending.wifi_samples,
            events=pending.events,
        )

        try:
            resp = self._client.post(
                f"{self._cfg.server_url}/api/v1/ingest",
                json=batch.model_dump(mode="json"),
                headers={
                    "X-Probe-Id": self._probe_id,
                    "Authorization": f"Bearer {self._token}",
                },
            )
        except httpx.HTTPError as exc:
            # The overwhelmingly common case: the network this system exists to debug is
            # down. Not an error condition -- it is the expected state during an outage.
            return ShipResult(ok=False, error=f"transport: {exc}")

        if resp.status_code in (401, 403):
            # Auth was rejected. Retrying with the same credentials cannot help; the
            # agent re-registers instead.
            return ShipResult(ok=False, fatal=True, error=f"auth rejected ({resp.status_code})")

        if resp.status_code == 400:
            return ShipResult(ok=False, fatal=True, error=f"rejected: {resp.text[:200]}")

        if resp.status_code == 413:
            # The batch exceeded the server's cap. Retrying it unchanged would loop
            # forever, so this is surfaced as fatal and the batch size must come down.
            return ShipResult(ok=False, fatal=True, error="batch too large; reduce ship_batch_size")

        if resp.status_code >= 500:
            return ShipResult(ok=False, error=f"server error {resp.status_code}")

        if resp.status_code not in (200, 202):
            return ShipResult(ok=False, error=f"unexpected status {resp.status_code}")

        # Parse into the shared model rather than reading raw dict keys: this validates
        # the server's response shape, so a protocol drift surfaces here instead of
        # silently yielding None for a field the server renamed.
        try:
            body = IngestResponse.model_validate(resp.json())
        except ValidationError as exc:
            return ShipResult(ok=False, fatal=True, error=f"malformed ingest response: {exc}")

        return ShipResult(
            ok=True,
            shipped=len(pending),
            duplicate=body.duplicate,
            config_revision=body.config_revision,
            clock_offset_ms=body.clock_offset_ms,
        )

    # -- backoff -----------------------------------------------------------

    def next_delay_s(self) -> float:
        """Exponential backoff with jitter, from the consecutive-failure count.

        Jitter matters with several probes on one network: without it they would fail
        together, back off together, and retry in a synchronized burst the moment
        connectivity returned -- exactly when the network is least able to absorb one.
        """
        if self._consecutive_failures == 0:
            return self._cfg.ship_interval_s

        delay: float = self._cfg.retry_base_delay_s * float(
            2 ** min(self._consecutive_failures - 1, 10)
        )
        delay = min(delay, self._cfg.retry_max_delay_s)
        return delay * (0.5 + random.random() * 0.5)

    def close(self) -> None:
        self._client.close()
