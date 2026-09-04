"""The engine: skipping, error isolation, and the CI exit contract."""

from __future__ import annotations

from qs_preflight.engine import run_rules
from qs_preflight.evidence import Evidence
from qs_preflight.findings import Severity, Status
from qs_preflight.rules.base import Rule
from qs_preflight.rules.oauth_scopes import OAuthScopesRule
from qs_preflight.rules.tool_count import ToolCountRule


def test_missing_evidence_skips_rather_than_fails():
    """A server requiring no authorization must not produce authorization
    failures. Missing evidence yields SKIP, not FAIL."""
    report = run_rules(Evidence(target="https://x/mcp"), rules=[ToolCountRule, OAuthScopesRule])
    assert all(f.status is Status.SKIP for f in report.findings)
    # Findings are sorted worst-first, so look the rule up rather than indexing.
    by_id = {f.rule_id: f for f in report.findings}
    assert "no tools" in by_id["tool-count"].headline
    assert report.exit_code() == 0


def test_a_broken_rule_does_not_sink_the_run(evidence):
    class ExplodingRule(Rule):
        id = "exploding"
        title = "always raises"
        severity = Severity.BLOCKER
        doc_verified = True

        def check(self, ev):
            raise RuntimeError("boom")

    report = run_rules(evidence(tool_count=5), rules=[ExplodingRule, ToolCountRule])
    statuses = {f.rule_id: f.status for f in report.findings}
    assert statuses["exploding"] is Status.ERROR
    assert statuses["tool-count"] is Status.PASS, "one bad rule must not cost the others"


def test_a_rule_error_is_exit_2_not_exit_1(evidence):
    """An inconclusive run must not be reported as success, and must be
    distinguishable from a target that genuinely failed a check."""

    class ExplodingRule(Rule):
        id = "exploding"
        title = "always raises"
        severity = Severity.BLOCKER
        doc_verified = True

        def check(self, ev):
            raise RuntimeError("boom")

    report = run_rules(evidence(tool_count=5), rules=[ExplodingRule])
    assert report.exit_code() == 2


def test_exit_codes(evidence):
    clean = run_rules(evidence(tool_count=10), rules=[ToolCountRule])
    assert clean.exit_code() == 0

    broken = run_rules(evidence(tool_count=142), rules=[ToolCountRule])
    assert broken.exit_code() == 1
    assert len(broken.blockers) == 1


def test_fail_on_warn_switch(evidence):
    from qs_preflight.rules.latency import LatencyWarnRule

    report = run_rules(evidence(failures=2), rules=[LatencyWarnRule])
    assert report.exit_code() == 0, "warnings alone do not fail a build by default"
    assert report.exit_code(fail_on_warn=True) == 1


def test_findings_are_ordered_worst_first(evidence):
    import qs_preflight.rules  # noqa: F401

    report = run_rules(evidence(tool_count=142, draft3=True, scopes=None))
    statuses = [f.status for f in report.findings]
    assert statuses == sorted(
        statuses, key=lambda s: ["FAIL", "ERROR", "SKIP", "PASS"].index(s.value)
    )
