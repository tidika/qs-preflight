"""What a rule returns, and what a run adds up to.

A rule never prints and never exits. It returns a `Finding`. Rendering and exit
codes belong elsewhere, which is what lets one rule feed the terminal, `--json`
and `--markdown` without three implementations of the same logic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How much a violation should hurt.

    BLOCKER: the integration will not work. Fix before launch.
    WARN:    it may work now and break later, or degrade quietly.
    INFO:    not checkable from outside; emitted as a to-do list.
    """

    BLOCKER = "BLOCKER"
    WARN = "WARN"
    INFO = "INFO"


class Status(str, Enum):
    """What the rule concluded.

    SKIP matters as much as PASS. Point a checker at a server with no
    authentication and a naive implementation reports five OAuth blockers --
    that is noise, and noise is how a tool gets uninstalled. A skipped rule
    must always carry a reason.

    ERROR means *the checker* broke, not the target. It is the difference
    between a defective target and an inconclusive run, and it selects a
    different exit code.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    status: Status
    headline: str
    doc_url: str
    detail: list[str] = field(default_factory=list)
    remediation: str = ""
    # True when this rule's behaviour was verified against a live Amazon Quick
    # account rather than only derived from documentation.
    verified: bool = False

    @property
    def is_blocking(self) -> bool:
        return self.status is Status.FAIL and self.severity is Severity.BLOCKER

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass(frozen=True)
class Report:
    target: str
    findings: list[Finding]
    probe_errors: dict[str, str] = field(default_factory=dict)

    def count(self, status: Status) -> int:
        return sum(1 for f in self.findings if f.status is status)

    @property
    def blockers(self) -> list[Finding]:
        return [f for f in self.findings if f.is_blocking]

    @property
    def warnings(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.status is Status.FAIL and f.severity is Severity.WARN
        ]

    @property
    def errored(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.ERROR]

    def exit_code(self, fail_on_warn: bool = False) -> int:
        """0 clean, 1 blockers present, 2 the tool itself failed.

        These three values form the continuous-integration contract. A change
        that introduces a 101st tool must fail the build, and a run that could
        not reach the server must not report success.
        """
        if self.errored:
            return 2
        if self.blockers:
            return 1
        if fail_on_warn and self.warnings:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "summary": {
                "blockers": len(self.blockers),
                "warnings": len(self.warnings),
                "passed": self.count(Status.PASS),
                "skipped": self.count(Status.SKIP),
                "errors": len(self.errored),
            },
            "probe_errors": self.probe_errors,
            "findings": [f.to_dict() for f in self.findings],
        }
