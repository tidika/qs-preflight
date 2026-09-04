"""The three output formats.

They must agree, because none of them decides anything -- they render the same
`Report`. A discrepancy between `--json` and the terminal would mean logic had
leaked into a renderer, which is exactly what the design is meant to prevent.
"""

from __future__ import annotations

import json

import qs_preflight.rules  # noqa: F401
from qs_preflight import report as reporters
from qs_preflight.engine import run_rules
from qs_preflight.findings import Status


def test_json_is_valid_and_carries_every_finding(evidence):
    report = run_rules(evidence(tool_count=142, draft3=True))
    payload = json.loads(reporters.render_json(report))

    assert payload["target"] == report.target
    assert len(payload["findings"]) == len(report.findings)
    assert payload["summary"]["blockers"] == len(report.blockers)


def test_json_and_terminal_cannot_disagree(evidence):
    """Both render the same Report, so the counts must match by construction."""
    report = run_rules(evidence(tool_count=142, draft3=True))
    payload = json.loads(reporters.render_json(report))

    assert payload["summary"]["passed"] == report.count(Status.PASS)
    assert payload["summary"]["skipped"] == report.count(Status.SKIP)
    assert payload["summary"]["warnings"] == len(report.warnings)


def test_markdown_is_pasteable_and_names_the_failures(evidence):
    report = run_rules(evidence(tool_count=142))
    out = reporters.render_markdown(report)

    assert out.startswith("## Amazon Quick MCP preflight")
    assert "| | Rule | Severity | Result |" in out
    assert "`tool-count`" in out
    assert "What needs fixing" in out
    assert "docs.aws.amazon.com" in out, "citations must survive into the paste"


def test_markdown_states_the_verdict_plainly(evidence):
    # A genuinely clean server: scopes declared, annotations declared, DCR offered.
    # Anything less and a WARN fires, which is a different verdict.
    clean = reporters.render_markdown(
        run_rules(
            evidence(
                tool_count=10,
                scopes=["mcp:tools"],
                annotate=True,
                registration_endpoint="https://auth.example.com/register",
            )
        )
    )
    assert "No blockers found" in clean

    broken = reporters.render_markdown(run_rules(evidence(tool_count=142)))
    assert "will not work with Amazon Quick" in broken


def test_markdown_distinguishes_warnings_from_blockers(evidence):
    """A server with warnings but no blockers gets a different verdict from one
    that will not work at all -- the reader needs to know which they have."""
    warned = reporters.render_markdown(run_rules(evidence(tool_count=10, scopes=["mcp:tools"])))
    assert "likely to work, with risks worth reading" in warned
    assert "will not work" not in warned


def test_terminal_renders_without_unicode_support(evidence):
    """Windows' legacy console is cp1252. The report must degrade, not crash."""
    import io

    from rich.console import Console

    buffer = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    console = Console(file=buffer, width=100, force_terminal=False)

    report = run_rules(evidence(tool_count=142, draft3=True))
    reporters.render_terminal(report, console=console)  # must not raise

    buffer.seek(0)
    text = buffer.buffer.getvalue().decode("cp1252")
    assert "tool-count" in text
    assert "Exit 1" in text


def test_terminal_marks_measured_findings(evidence):
    import io

    from rich.console import Console

    buffer = io.StringIO()
    console = Console(file=buffer, width=120)
    reporters.render_terminal(run_rules(evidence(tool_count=142)), console=console)

    assert "[measured]" in buffer.getvalue()
