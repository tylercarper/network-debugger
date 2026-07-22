"""DNS collector.

DNS is queried against several resolvers deliberately, because the *asymmetry* between
them is what localizes a fault. If the gateway's resolver fails while 1.1.1.1 answers,
the router's forwarder is the problem; if every resolver fails while ICMP still works,
the fault is upstream or DNS is being filtered. A single resolver cannot tell these
apart, and "DNS is slow" is one of the most common real causes of "full bars, no
internet".

Two things are recorded beyond success and timing:

* **rcode**, so NXDOMAIN (a working resolver saying "no such name") is not mistaken for a
  failure to reach the resolver at all.
* **whether the answer changed**, because a resolver returning a *different* address for
  a normally-stable name is a real failure mode -- an ISP or router injecting a redirect,
  which presents to the user as the internet being broken while DNS technically "works".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

import dns.exception
import dns.resolver

from netdbg_common.enums import SampleKind
from netdbg_common.models import Sample

__all__ = ["DnsProbe", "DnsTarget", "Resolvable", "resolve_once"]


class Resolvable(Protocol):
    """The slice of a dnspython Resolver this collector uses.

    Narrowing to a Protocol lets a stub resolver satisfy the type without subclassing
    the real one, which keeps the tests honest -- they exercise the same call path.
    """

    def resolve(self, name: Any, rdtype: Any = ..., *args: Any, **kwargs: Any) -> Any: ...


# Names to resolve, rotated to defeat resolver caching -- a cached answer measures the
# cache, not the resolver's path to the internet. These are stable, widely-hosted names
# whose answers change rarely, so a changed answer is signal rather than noise.
_QUERY_NAMES = (
    "cloudflare.com",
    "google.com",
    "wikipedia.org",
    "example.com",
)

# DNS rcodes worth distinguishing. NOERROR with no answer and NXDOMAIN both mean the
# resolver was *reached* -- very different from a timeout, which means it was not.
_RCODE_NOERROR = 0
_RCODE_NXDOMAIN = 3


@dataclass(frozen=True, slots=True)
class DnsTarget:
    """A resolver to query, with the label its samples are recorded under."""

    address: str
    label: str


class DnsProbe:
    """Resolves rotating names against a resolver and records timing and drift.

    Holds a little state -- the last answer seen per name -- so it can detect when a
    normally-stable name starts resolving to something different.
    """

    def __init__(self, target: DnsTarget, timeout_s: float = 2.0) -> None:
        self._target = target
        self._timeout_s = timeout_s
        self._resolver = dns.resolver.Resolver(configure=False)
        self._resolver.nameservers = [target.address]
        self._resolver.timeout = timeout_s
        self._resolver.lifetime = timeout_s
        self._query_index = 0
        self._last_answers: dict[str, frozenset[str]] = {}

    def resolve(self, ts: int, *, seq: int | None = None) -> Sample:
        """Resolve the next rotating name once. Always returns a Sample, never raises."""
        name = _QUERY_NAMES[self._query_index % len(_QUERY_NAMES)]
        self._query_index += 1
        return resolve_once(
            self._resolver,
            self._target,
            name,
            ts,
            seq=seq,
            last_answers=self._last_answers,
        )


def resolve_once(
    resolver: Resolvable,
    target: DnsTarget,
    name: str,
    ts: int,
    *,
    seq: int | None = None,
    last_answers: dict[str, frozenset[str]] | None = None,
) -> Sample:
    """Perform one resolution and classify the outcome.

    Pulled out as a free function so it can be tested with a stub resolver, without the
    per-name rotation state of :class:`DnsProbe`.
    """
    start = time.perf_counter()
    try:
        answer = resolver.resolve(name, "A", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        # The resolver was reached and authoritatively said "no such name". That is a
        # working resolver, not a failure to reach it -- so success is True, and the
        # rcode carries the distinction.
        return Sample(
            ts=ts,
            kind=SampleKind.DNS,
            target=target.label,
            success=True,
            value_ms=(time.perf_counter() - start) * 1000,
            code=_RCODE_NXDOMAIN,
            seq=seq,
        )
    except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers):
        # Could not reach the resolver. This is the failure that matters: no value_ms,
        # because there is no timing for a query that never completed.
        return Sample(ts=ts, kind=SampleKind.DNS, target=target.label, success=False, seq=seq)
    except dns.exception.DNSException:
        # Any other DNS-layer error is a failure, but a distinct one from a timeout.
        return Sample(
            ts=ts, kind=SampleKind.DNS, target=target.label, success=False, code=-1, seq=seq
        )

    elapsed_ms = (time.perf_counter() - start) * 1000

    # Detect a changed answer for a normally-stable name. A resolver handing back a
    # different address than last time -- for a name that does not normally move -- is
    # the signature of injected DNS, which looks to the user like the internet is broken.
    answer_changed = False
    if last_answers is not None and answer.rrset is not None:
        current = frozenset(str(r) for r in answer.rrset)
        previous = last_answers.get(name)
        if previous is not None and previous != current:
            answer_changed = True
        last_answers[name] = current

    # code encodes the outcome: NOERROR normally, or a sentinel when the answer drifted,
    # so the server can flag possible DNS injection without a separate column.
    code = 100 if answer_changed else _RCODE_NOERROR
    return Sample(
        ts=ts,
        kind=SampleKind.DNS,
        target=target.label,
        success=True,
        value_ms=elapsed_ms,
        code=code,
        seq=seq,
    )
