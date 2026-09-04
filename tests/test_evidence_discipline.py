"""The rule about the rules.

A fifth of this project's value is that no check was invented from vibes. That is
a property worth enforcing in CI rather than trusting to memory, so these tests
fail the build if a rule ever ships without a citation a human has confirmed.

A compatibility checker whose own citations were guessed would refute its own
premise.
"""

from __future__ import annotations

import qs_preflight.rules  # noqa: F401  -- populates the registry
from qs_preflight import docs
from qs_preflight.rules.base import REGISTRY


def test_every_registered_rule_has_a_verified_citation():
    unverified = [r.id for r in REGISTRY if not r.doc_verified]
    assert not unverified, (
        f"rules with unverified citations: {unverified}. "
        "Open the documentation, confirm it states the constraint, record the URL "
        "and today's date in docs.CITATIONS, then set doc_verified = True."
    )


def test_no_rule_ships_a_placeholder_url():
    placeholders = [r.id for r in REGISTRY if r().doc_url == docs.UNVERIFIED]
    assert not placeholders, f"rules still pointing at UNVERIFIED: {placeholders}"


def test_every_registered_rule_has_a_citation_entry():
    missing = [r.id for r in REGISTRY if r.id not in docs.CITATIONS]
    assert not missing, f"rules with no entry in docs.CITATIONS: {missing}"


def test_every_citation_carries_a_verbatim_quote():
    """The quote is what makes drift detectable. AWS has renamed this product
    twice in under a year; the page will change again."""
    thin = [
        rid
        for rid, c in docs.CITATIONS.items()
        if c.url != docs.UNVERIFIED and len(c.quote) < 40
    ]
    assert not thin, f"citations without a usable quote: {thin}"


def test_every_citation_records_when_it_was_checked():
    undated = [
        rid
        for rid, c in docs.CITATIONS.items()
        if c.url != docs.UNVERIFIED and not c.retrieved
    ]
    assert not undated, f"citations with no retrieval date: {undated}"


def test_rule_ids_are_unique():
    ids = [r.id for r in REGISTRY]
    assert len(ids) == len(set(ids))
