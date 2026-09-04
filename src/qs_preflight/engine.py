"""Runs every registered rule over one evidence bundle."""

from __future__ import annotations

from .evidence import Evidence
from .findings import Report, Status
from .rules.base import REGISTRY, Rule

# Failures first, then errors, then skips, then passes -- so the terminal shows
# what needs acting on before what does not.
_STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "SKIP": 2, "PASS": 3}
_SEVERITY_ORDER = {"BLOCKER": 0, "WARN": 1, "INFO": 2}


def run_rules(ev: Evidence, rules: list[type[Rule]] | None = None) -> Report:
    findings = []

    for rule_cls in rules if rules is not None else REGISTRY:
        rule = rule_cls()

        missing = [k for k in rule.requires if not ev.has(k)]
        if missing:
            findings.append(
                rule.skipped(f"not evaluated: probe collected no {', '.join(missing)}")
            )
            continue

        try:
            findings.append(rule.check(ev))
        except Exception as exc:
            # One broken rule must not cost the other thirteen results, and it
            # must not be reported as the target's fault.
            findings.append(rule.errored(f"rule raised {type(exc).__name__}: {exc}"))

    findings.sort(
        key=lambda f: (
            _STATUS_ORDER[f.status.value],
            _SEVERITY_ORDER[f.severity.value],
            f.rule_id,
        )
    )
    return Report(target=ev.target, findings=findings, probe_errors=dict(ev.probe_errors))
