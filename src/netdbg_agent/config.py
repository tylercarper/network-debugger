"""Agent configuration.

A probe needs only two things to join: the server address and a name. Everything else
has a working default, because the deployment story is "copy this to a Pi and start it",
not "write a config file first".
"""

from __future__ import annotations

import socket
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["AgentConfig", "get_config"]


class AgentConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETDBG_", env_file=".env", extra="ignore")

    server_url: str = "http://localhost:8080"
    name: str = ""
    """Probe name. Defaults to the hostname, which is usually what you want."""

    state_dir: Path = Path("data/agent")
    """Holds the spool database and the persisted probe identity."""

    # --- Shipping -----------------------------------------------------------

    ship_interval_s: float = 5.0
    ship_batch_size: int = 1000
    """Rows per batch. Must stay under the server's max_batch_samples (5000).

    Kept well below it so a batch of samples plus wifi samples cannot cross the limit
    and start bouncing off a 413 forever.
    """

    ship_timeout_s: float = 10.0

    retry_base_delay_s: float = 1.0
    retry_max_delay_s: float = 300.0
    """Backoff ceiling: 5 minutes.

    During a long outage the agent should keep measuring and keep buffering, not hammer
    an unreachable server. But the ceiling must stay low enough that recovery is noticed
    promptly -- a probe that waits an hour to retry turns a 10-minute outage into an
    hour-long hole in the timeline.
    """

    # --- Spool bounds -------------------------------------------------------

    spool_max_rows: int = 2_000_000
    """Hard cap on buffered rows before dropping the oldest.

    At ~4 samples/s this is roughly 5 days of buffering -- far longer than any plausible
    outage, so in practice the cap should never be reached. It exists so a probe that
    somehow never reconnects fills its disk with a bounded amount rather than an
    unbounded one.
    """

    spool_trim_check_interval_s: float = 300.0

    def resolved_name(self) -> str:
        return self.name or socket.gethostname()


_config: AgentConfig | None = None


def get_config() -> AgentConfig:
    global _config
    if _config is None:
        _config = AgentConfig()
    return _config
