"""SQLite connection management and pragma configuration.

SQLite fits this workload well: one writer, modest volume, and a single file that an
analysis agent can open read-only for arbitrary SQL. The pragmas below are what make it
behave under continuous ingest on a Pi.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["apply_pragmas", "connect", "connect_readonly", "init_db", "transaction"]

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# WAL lets readers (dashboard, analysis agent) run concurrently with the ingest writer
# instead of blocking on it.
#
# synchronous=NORMAL rather than FULL: with WAL this is crash-safe, and only risks the
# last transactions on sudden power loss. FULL would fsync every commit, which on a
# sustained multi-sample-per-second write path is a large cost to avoid losing at most
# a second of monitoring data.
#
# busy_timeout matters because the detection pass, retention job, and ingest all write.
# Without it a concurrent write fails immediately rather than waiting its turn.
_PRAGMAS = (
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("busy_timeout", "5000"),
    ("foreign_keys", "ON"),
    # Checkpoint roughly every 2000 pages. Left at the default the WAL can grow large
    # under continuous ingest; checkpointing too eagerly stalls writers.
    ("wal_autocheckpoint", "2000"),
    ("temp_store", "MEMORY"),
)


def apply_pragmas(conn: sqlite3.Connection) -> None:
    """Apply connection pragmas. Must run on every connection, not just at init."""
    for name, value in _PRAGMAS:
        conn.execute(f"PRAGMA {name} = {value}")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a read-write connection with pragmas applied.

    Uses ``isolation_level=None`` so transactions are explicit via :func:`transaction`
    rather than implicitly opened by the driver -- with an implicit transaction it is
    easy to hold a write lock far longer than intended during a long ingest loop.
    """
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    apply_pragmas(conn)
    return conn


def connect_readonly(db_path: str | Path) -> sqlite3.Connection:
    """Open a read-only connection.

    This is the analysis-agent path: WAL makes concurrent reads safe against the ingest
    writer, and ``mode=ro`` plus ``query_only`` means a bad query cannot mutate anything.
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA query_only = ON")
    return conn


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Create the schema if absent and return an open connection.

    The schema is idempotent (``CREATE TABLE IF NOT EXISTS`` throughout), so this is
    safe to call on every server start.
    """
    conn = connect(db_path)
    conn.executescript(_SCHEMA_PATH.read_text())
    apply_pragmas(conn)  # executescript can reset some pragmas; reassert them
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Explicit transaction that commits on success and rolls back on any exception.

    IMMEDIATE acquires the write lock up front. Deferring it risks failing partway
    through a multi-statement write when another writer got there first, which for a
    batch insert means partially-applied data.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
