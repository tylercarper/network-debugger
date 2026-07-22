"""HTTP connectivity and captive-portal collector.

This is the non-ICMP signal, and its main job is to keep the headline detector honest.
Routers and ISPs routinely rate-limit or drop ICMP to their own control plane, so ping
to 1.1.1.1 can fail while real traffic flows fine. If a ``gateway_up_internet_down``
verdict rested on ICMP alone it would cry wolf constantly. An HTTP check that *succeeds*
while ICMP fails means the internet is actually up and ICMP is merely filtered -- a
completely different, low-severity finding.

The probe fetches a known-204 endpoint. The response classifies the connection:

* **204 No Content** -> clean, unintercepted internet.
* **3xx / 200-with-body** -> a captive portal or transparent proxy is intercepting. To
  the user this is "connected but nothing loads", which is exactly the reported symptom.
* **timeout / connection error** -> down.

A second HTTPS request separates plaintext interception (HTTP intercepted, HTTPS still
works) from a total outage (both fail).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from netdbg_common.enums import SampleKind
from netdbg_common.models import Sample

__all__ = ["Gettable", "HttpProbe", "HttpTarget", "check_once"]


class Gettable(Protocol):
    """The slice of httpx.Client this collector uses.

    A Protocol so a stub client can stand in for tests without constructing real HTTP
    machinery, while still exercising the same call path.
    """

    def get(self, url: Any, *args: Any, **kwargs: Any) -> Any: ...


# Google's generate_204 is the canonical connectivity-check endpoint: it returns 204 with
# an empty body, so any other response means something sits between the probe and the
# internet. Plain HTTP on purpose -- HTTPS cannot be transparently intercepted without a
# certificate error, so HTTP is where a captive portal shows itself.
DEFAULT_CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"

# An HTTPS control. If the plain-HTTP check above is intercepted but this still succeeds,
# the internet is up and only unencrypted traffic is being redirected.
DEFAULT_HTTPS_URL = "https://www.google.com/generate_204"

# Result codes stored in Sample.code, so the server can classify without a body.
CODE_CLEAN = 204
CODE_CAPTIVE_PORTAL = 1
CODE_UNEXPECTED_STATUS = 2
CODE_TIMEOUT = 3
CODE_CONNECTION_ERROR = 4


@dataclass(frozen=True, slots=True)
class HttpTarget:
    url: str
    label: str
    expect_status: int = 204


class HttpProbe:
    """Checks connectivity against a 204 endpoint and detects interception."""

    def __init__(self, target: HttpTarget, timeout_s: float = 5.0) -> None:
        self._target = target
        # follow_redirects=False is essential: a captive portal answers with a 302 to its
        # login page, and following it would turn the tell-tale redirect into an
        # ordinary 200 and hide the interception.
        self._client = httpx.Client(timeout=timeout_s, follow_redirects=False)

    def check(self, ts: int, *, seq: int | None = None) -> Sample:
        return check_once(self._client, self._target, ts, seq=seq)

    def close(self) -> None:
        self._client.close()


def check_once(client: Gettable, target: HttpTarget, ts: int, *, seq: int | None = None) -> Sample:
    """Perform one connectivity check. Always returns a Sample, never raises.

    Separated from :class:`HttpProbe` so it can be driven with a stub client in tests.
    """
    try:
        resp = client.get(target.url)
    except httpx.TimeoutException:
        return Sample(
            ts=ts,
            kind=SampleKind.HTTP,
            target=target.label,
            success=False,
            code=CODE_TIMEOUT,
            seq=seq,
        )
    except httpx.HTTPError:
        # Connection refused/reset/DNS failure -- reachable network stack, no working
        # path to the endpoint.
        return Sample(
            ts=ts,
            kind=SampleKind.HTTP,
            target=target.label,
            success=False,
            code=CODE_CONNECTION_ERROR,
            seq=seq,
        )

    elapsed_ms = resp.elapsed.total_seconds() * 1000

    if resp.status_code == target.expect_status:
        # Clean: the expected empty 204, nothing in the path.
        return Sample(
            ts=ts,
            kind=SampleKind.HTTP,
            target=target.label,
            success=True,
            value_ms=elapsed_ms,
            code=CODE_CLEAN,
            seq=seq,
        )

    if resp.status_code in (301, 302, 303, 307, 308) or (
        resp.status_code == 200 and len(resp.content) > 0
    ):
        # A redirect, or a 200 with a body where an empty 204 was expected, means
        # something answered on the endpoint's behalf -- a captive portal or proxy.
        # success is True: bytes flowed, so this is not an outage. It is interception,
        # which the server treats as its own condition.
        return Sample(
            ts=ts,
            kind=SampleKind.HTTP,
            target=target.label,
            success=True,
            value_ms=elapsed_ms,
            code=CODE_CAPTIVE_PORTAL,
            seq=seq,
        )

    # Some other status. Reachable but not behaving as expected.
    return Sample(
        ts=ts,
        kind=SampleKind.HTTP,
        target=target.label,
        success=True,
        value_ms=elapsed_ms,
        code=CODE_UNEXPECTED_STATUS,
        seq=seq,
    )
