"""DNS collector tests.

The distinctions this collector draws are the whole point: reached-but-no-such-name
versus could-not-reach, and answer-stable versus answer-changed. Each corresponds to a
different diagnosis, so each gets an explicit test. The collector must never raise -- a
DNS failure is a measurement.
"""

from __future__ import annotations

import typing
from typing import Any
from unittest.mock import MagicMock

import dns.resolver
import pytest

from netdbg_agent.collectors.dns_probe import DnsProbe, DnsTarget, resolve_once
from netdbg_common.enums import SampleKind

NOW = 1_700_000_000_000
TARGET = DnsTarget(address="1.1.1.1", label="dns-cloudflare")


class StubResolver:
    """A resolver whose behaviour is scripted per call."""

    def __init__(self, behaviour: Any) -> None:
        self._behaviour = behaviour

    def resolve(self, name: Any, rdtype: Any = "A", *args: Any, **kwargs: Any) -> Any:
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return self._behaviour


def _answer(*addresses: str) -> MagicMock:
    ans = MagicMock()
    ans.rrset = [MagicMock(__str__=lambda self, a=a: a) for a in addresses]
    return ans


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------


def test_successful_resolution_records_timing() -> None:
    sample = resolve_once(StubResolver(_answer("1.2.3.4")), TARGET, "example.com", NOW)

    assert sample.success
    assert sample.kind == SampleKind.DNS
    assert sample.value_ms is not None
    assert sample.target == "dns-cloudflare"


def test_timeout_is_a_failure_with_no_timing() -> None:
    """A query that never completed has no duration to report."""
    sample = resolve_once(StubResolver(dns.resolver.LifetimeTimeout()), TARGET, "example.com", NOW)

    assert not sample.success
    assert sample.value_ms is None


def test_nxdomain_is_success_not_failure() -> None:
    """A resolver that authoritatively says "no such name" is *working*.

    Treating NXDOMAIN as a resolver failure would flag a healthy resolver as broken --
    and mask the real signal, which is a resolver that cannot be reached at all.
    """
    sample = resolve_once(StubResolver(dns.resolver.NXDOMAIN()), TARGET, "nope.invalid", NOW)

    assert sample.success, "NXDOMAIN means the resolver answered"
    assert sample.code == 3, "rcode should record NXDOMAIN distinctly"


def test_no_nameservers_is_a_failure() -> None:
    sample = resolve_once(StubResolver(dns.resolver.NoNameservers()), TARGET, "example.com", NOW)
    assert not sample.success


def test_collector_never_raises() -> None:
    """Any DNS-layer exception becomes a failed Sample, not a crash."""
    sample = resolve_once(
        StubResolver(dns.exception.DNSException("weird")), TARGET, "example.com", NOW
    )
    assert not sample.success


# ---------------------------------------------------------------------------
# Answer-change detection -- injected DNS
# ---------------------------------------------------------------------------


def test_stable_answer_is_not_flagged() -> None:
    """The same answer twice is normal and must not raise a false injection flag."""
    seen: dict[str, frozenset[str]] = {}
    first = resolve_once(
        StubResolver(_answer("1.2.3.4")), TARGET, "bank.example", NOW, last_answers=seen
    )
    second = resolve_once(
        StubResolver(_answer("1.2.3.4")), TARGET, "bank.example", NOW, last_answers=seen
    )

    assert first.code == 0
    assert second.code == 0, "an unchanged answer must not be flagged"


def test_changed_answer_is_flagged() -> None:
    """A normally-stable name resolving somewhere new is the signature of injected DNS.

    An ISP or router redirecting a name presents to the user as the internet being
    broken while DNS technically 'works', so it must be surfaced.
    """
    seen: dict[str, frozenset[str]] = {}
    resolve_once(StubResolver(_answer("1.2.3.4")), TARGET, "bank.example", NOW, last_answers=seen)
    changed = resolve_once(
        StubResolver(_answer("9.9.9.9")), TARGET, "bank.example", NOW, last_answers=seen
    )

    assert changed.success, "the query still succeeded"
    assert changed.code == 100, "a changed answer should be flagged distinctly"


def test_first_answer_is_never_flagged() -> None:
    """With no prior answer to compare against, nothing is a change."""
    seen: dict[str, frozenset[str]] = {}
    first = resolve_once(
        StubResolver(_answer("1.2.3.4")), TARGET, "x.example", NOW, last_answers=seen
    )
    assert first.code == 0


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


def test_probe_rotates_query_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rotating names defeats resolver caching.

    A cached answer measures the cache, not the resolver's path to the internet -- so a
    resolver that has gone deaf but still serves cache would look healthy.
    """
    queried: list[str] = []

    class RecordingResolver:
        nameservers: typing.ClassVar[list[str]] = []
        timeout = 2.0
        lifetime = 2.0

        def resolve(self, name: Any, rdtype: Any = "A", *args: Any, **kwargs: Any) -> Any:
            queried.append(name)
            return _answer("1.2.3.4")

    probe = DnsProbe(TARGET)
    monkeypatch.setattr(probe, "_resolver", RecordingResolver())

    for i in range(5):
        probe.resolve(NOW + i)

    assert len(set(queried)) > 1, "the probe should rotate through multiple names"
