"""Rich terminal output.

This is the format people will actually read, and the one that ends up in a
screenshot. Two rules govern it:

Every finding carries its citation. A report that says "this will fail" without
saying who says so is an assertion; with the doc URL attached it is an argument
the reader can check. That is the whole premise of the tool, so the URL is never
dropped for tidiness.

Findings established by direct observation are marked as measured. Where
observation and AWS documentation diverge, which is substantial for the
tool-count rule, the distinction is made explicit in the output.
"""

from __future__ import annotations

from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from ..findings import Report, Severity, Status

_SYMBOL_UNICODE = {
    Status.FAIL: "✗",
    Status.PASS: "✓",
    Status.SKIP: "○",
    Status.ERROR: "!",
}

# Windows' legacy console encodes as cp1252 and raises on the glyphs above.
# Degrading is better than crashing: a checker that cannot print its own report
# on a common platform is not adoptable.
_SYMBOL_ASCII = {
    Status.FAIL: "x",
    Status.PASS: "+",
    Status.SKIP: "-",
    Status.ERROR: "!",
}


def _symbols(console: Console) -> tuple[dict[Status, str], str, str]:
    """Pick glyphs the target stream can actually encode."""
    encoding = getattr(console.file, "encoding", None) or "ascii"
    try:
        "✗✓○→—".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return _SYMBOL_ASCII, "-", "->"
    return _SYMBOL_UNICODE, "—", "→"

_STYLE = {
    (Status.FAIL, Severity.BLOCKER): "bold red",
    (Status.FAIL, Severity.WARN): "bold yellow",
    (Status.FAIL, Severity.INFO): "cyan",
    (Status.ERROR, Severity.BLOCKER): "bold magenta",
}

_INDENT = " " * 4
# Detail is indented via rich's Padding rather than string concatenation, so
# wrapped lines stay aligned under the block instead of falling back to column
# zero. A report that looks broken in an 80-column terminal will not be trusted.
_DETAIL_PAD = (0, 0, 0, 11)


def render(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    symbol, dash, arrow = _symbols(console)
    findings = report.findings

    # A run that never reached the target evaluated no rules, so reporting a
    # rule count would be misleading.
    inconclusive = len(findings) == 1 and findings[0].rule_id == "target-unreachable"
    subtitle = "" if inconclusive else f" {dash} {len(findings)} rules"

    console.print()
    console.print(
        Text.assemble(
            ("  Amazon Quick MCP Preflight", "bold"),
            (subtitle, "dim"),
        )
    )
    console.print(Text(f"  {report.target}", style="dim"))
    console.print()

    for f in findings:
        style = _STYLE.get((f.status, f.severity))
        if style is None:
            style = "green" if f.status is Status.PASS else "dim"

        line = Text(_INDENT)
        line.append(f"{symbol[f.status]}  ", style=style)
        line.append(f"{f.severity.value:<8}", style=style)
        line.append(f"{f.rule_id:<22}", style="bold" if f.status is Status.FAIL else "")
        line.append(f.headline)
        if f.verified:
            line.append("  [measured]", style="dim cyan")
        console.print(line)

        # Detail and citation only where they earn their place: a wall of text
        # under every passing rule would bury the two lines that matter.
        if f.status in (Status.FAIL, Status.ERROR, Status.SKIP) and f.detail:
            for detail in f.detail:
                console.print(Padding(Text(detail, style="dim"), _DETAIL_PAD, expand=False))

        if f.status in (Status.FAIL, Status.ERROR):
            if f.remediation:
                console.print(
                    Padding(Text(f"{arrow} {f.remediation}", style="cyan"), _DETAIL_PAD, expand=False)
                )
            console.print(
                Padding(Text(f.doc_url, style="dim blue"), _DETAIL_PAD, expand=False)
            )
            console.print()

    _summary(report, console)


def _summary(report: Report, console: Console) -> None:
    blockers = len(report.blockers)
    warnings = len(report.warnings)
    passed = report.count(Status.PASS)
    skipped = report.count(Status.SKIP)
    errors = len(report.errored)

    parts = []
    parts.append((f"{blockers} blocker{'s' if blockers != 1 else ''}",
                  "bold red" if blockers else "dim"))
    parts.append((f"{warnings} warning{'s' if warnings != 1 else ''}",
                  "bold yellow" if warnings else "dim"))
    parts.append((f"{passed} passed", "green" if passed else "dim"))
    if skipped:
        parts.append((f"{skipped} skipped", "dim"))
    if errors:
        parts.append((f"{errors} errored", "bold magenta"))

    line = Text("  ")
    for i, (text, style) in enumerate(parts):
        if i:
            line.append(", ", style="dim")
        line.append(text, style=style)
    line.append(f".  Exit {report.exit_code()}.", style="dim")

    console.print()
    console.print(line)

    if report.probe_errors:
        console.print()
        console.print(Text("  The probe could not complete everything:", style="dim"))
        for key, value in report.probe_errors.items():
            console.print(Text(f"    {key}: {value}", style="dim"))
    console.print()
