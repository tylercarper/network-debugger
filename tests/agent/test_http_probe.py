"""HTTP / captive-portal collector tests.

The classification is the reason this collector exists: 204 clean, redirect-or-body means
interception, timeout means down. Interception in particular must be recorded as a
*success* (bytes flowed) with a distinct code, because it is not an outage -- it is the
"connected but nothing loads" symptom, which needs its own treatment.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx

from netdbg_agent.collectors.http_probe import (
    CODE_CAPTIVE_PORTAL,
    CODE_CLEAN,
    CODE_CONNECTION_ERROR,
    CODE_TIMEOUT,
    HttpTarget,
    check_once,
)
from netdbg_common.enums import SampleKind

NOW = 1_700_000_000_000
TARGET = HttpTarget(url="http://check.example/generate_204", label="http-check")


class StubClient:
    def __init__(self, response_or_exc: Any) -> None:
        self._r = response_or_exc

    def get(self, url: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(self._r, Exception):
            raise self._r
        return self._r


def _response(status: int, body: bytes = b"", elapsed_s: float = 0.05) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.elapsed = httpx.Timeout(elapsed_s)  # any object with total_seconds()
    resp.elapsed = MagicMock(total_seconds=lambda: elapsed_s)
    return resp


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_204_is_clean() -> None:
    sample = check_once(StubClient(_response(204)), TARGET, NOW)

    assert sample.success
    assert sample.code == CODE_CLEAN
    assert sample.kind == SampleKind.HTTP
    assert sample.value_ms is not None


def test_redirect_is_captive_portal() -> None:
    """A 302 to a login page is the classic captive-portal tell.

    Recorded as success -- bytes flowed -- but with the portal code, because it is
    interception, not an outage.
    """
    sample = check_once(StubClient(_response(302)), TARGET, NOW)

    assert sample.success
    assert sample.code == CODE_CAPTIVE_PORTAL


def test_200_with_body_is_captive_portal() -> None:
    """Where an empty 204 was expected, a 200 carrying HTML means a proxy answered.

    This is the "connected but every page is the ISP's notice page" case.
    """
    sample = check_once(StubClient(_response(200, body=b"<html>login here</html>")), TARGET, NOW)

    assert sample.success
    assert sample.code == CODE_CAPTIVE_PORTAL


def test_timeout_is_down() -> None:
    sample = check_once(StubClient(httpx.TimeoutException("slow")), TARGET, NOW)

    assert not sample.success
    assert sample.code == CODE_TIMEOUT


def test_connection_error_is_down() -> None:
    sample = check_once(StubClient(httpx.ConnectError("refused")), TARGET, NOW)

    assert not sample.success
    assert sample.code == CODE_CONNECTION_ERROR


def test_timeout_and_connection_error_are_distinguished() -> None:
    """A hung connection and a refused one are different network conditions."""
    timeout = check_once(StubClient(httpx.TimeoutException("x")), TARGET, NOW)
    refused = check_once(StubClient(httpx.ConnectError("x")), TARGET, NOW)

    assert timeout.code != refused.code


def test_collector_never_raises() -> None:
    """Even an unexpected status must yield a Sample, not an exception."""
    sample = check_once(StubClient(_response(500)), TARGET, NOW)
    assert sample.kind == SampleKind.HTTP
