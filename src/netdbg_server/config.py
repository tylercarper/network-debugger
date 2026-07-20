"""Server configuration.

Everything is overridable via ``NETDBG_`` environment variables, which is what the
Docker compose dev environment and the Pi systemd unit both use.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["ServerConfig", "get_config"]


class ServerConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETDBG_", env_file=".env", extra="ignore")

    db_path: Path = Path("data/netdbg.db")

    # Bind to all interfaces by default: the server must be reachable from probes
    # elsewhere on the LAN. Do not port-forward this -- see auth note below.
    host: str = "0.0.0.0"
    port: int = 8080

    auto_approve_probes: bool = True
    """Register probes straight to 'active' rather than 'pending'.

    Correct default for a home LAN, where the alternative is walking to another room to
    approve a probe you just installed. Set false if the network is untrusted.
    """

    max_batch_samples: int = 5000
    """Reject larger batches with 413.

    A probe backfilling hours of spooled data could otherwise send a single enormous
    request and exhaust memory on the Pi. The agent chunks to this size; the cap is what
    makes that contract enforceable.
    """

    max_clock_skew_warn_ms: int = 30_000
    """Skew beyond this is recorded and surfaced, not rejected.

    Rejecting skewed data would discard exactly what a struggling probe reports. Instead
    it is stored with the offset so correlation can degrade its confidence later.
    """

    config_revision: int = 1
    """Bumped when probe config changes; agents refetch only when it moves.

    This is the whole config-push channel -- it rides on the ingest response, so there
    is no separate control plane to build or keep alive.
    """


_config: ServerConfig | None = None


def get_config() -> ServerConfig:
    global _config
    if _config is None:
        _config = ServerConfig()
    return _config
