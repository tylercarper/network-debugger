"""Agent entry point."""

from __future__ import annotations

import logging

from netdbg_agent.config import get_config
from netdbg_agent.runner import AgentRunner
from netdbg_agent.shipper import Shipper
from netdbg_agent.spool import Spool

__all__ = ["main"]


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    log = logging.getLogger("netdbg.agent")

    cfg = get_config()
    spool = Spool(cfg.state_dir / "spool.db", max_rows=cfg.spool_max_rows)
    shipper = Shipper(cfg, spool)
    runner = AgentRunner(config=cfg, spool=spool, shipper=shipper)

    log.info("probe %s -> %s", cfg.resolved_name(), cfg.server_url)
    log.info("targets: %s", ", ".join(f"{t.label}={t.address}" for t in runner.targets))

    if backlog := spool.pending_count():
        # A non-empty spool at startup means the last run ended with data undelivered --
        # worth surfacing, since it is evidence of an outage that spanned a restart.
        log.info("resuming with %d buffered samples from a previous run", backlog)

    try:
        runner.run_forever()
    except KeyboardInterrupt:
        log.info("shutting down; %d samples remain spooled", spool.pending_count())
    finally:
        shipper.close()
        spool.close()


if __name__ == "__main__":
    main()
