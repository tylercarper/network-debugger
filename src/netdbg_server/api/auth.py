"""Probe authentication.

Deliberately minimal: a bearer token per probe, stored hashed. This is a home LAN, and
the threat model is "stop a stray device from polluting the dataset", not "resist an
attacker on the wire".

TLS/mTLS was considered and rejected. Certificate expiry would become a new failure mode
*in the system whose job is to diagnose failures* -- and it would fail silently, months
later, looking exactly like the network problem being investigated. Bind to the LAN and
do not port-forward instead.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3

from fastapi import Header, HTTPException, Request, status

__all__ = ["generate_token", "hash_token", "require_probe", "verify_token"]


def generate_token() -> str:
    """Issue a probe token. 32 bytes of urandom, URL-safe."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash for storage.

    Plain SHA-256 rather than a slow KDF: these are 256-bit random tokens, not
    user-chosen passwords, so there is no dictionary space to brute force and the
    stretching a KDF provides buys nothing here.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token(token: str, stored_hash: str) -> bool:
    """Constant-time comparison, to avoid leaking a prefix match via timing."""
    return hmac.compare_digest(hash_token(token), stored_hash)


def _extract_bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization[7:].strip()


def require_probe(
    request: Request,
    x_probe_id: str = Header(..., alias="X-Probe-Id"),
    authorization: str | None = Header(default=None),
) -> str:
    """FastAPI dependency: authenticate a probe, returning its id.

    Any failure is a flat 401 with no detail about *which* part failed -- an unknown
    probe id and a bad token are indistinguishable to the caller.
    """
    token = _extract_bearer(authorization)
    conn: sqlite3.Connection = request.app.state.db

    row = conn.execute(
        "SELECT auth_token_hash, status FROM probes WHERE probe_id = ?", (x_probe_id,)
    ).fetchone()

    if (
        row is None
        or row["auth_token_hash"] is None
        or not verify_token(token, row["auth_token_hash"])
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown probe or invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # A retired probe is rejected distinctly: it authenticated fine, so the operator
    # needs to know it is still running and trying to report, not that its token broke.
    if row["status"] == "retired":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Probe is retired; re-register to resume reporting",
        )

    return x_probe_id
