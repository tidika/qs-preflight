"""Operation latency against Amazon Quick's fixed 60-second timeout.

Two considerations make this stricter than the published limit suggests.

The rule reports the 95th percentile rather than a single reading, because one
sample gives no indication of the behaviour of the slowest calls.

Amazon Quick was observed on 2026-08-27 to re-initialize on every operation: a
single user query issues ``initialize``, ``notifications/initialized``,
``tools/list`` and then ``tools/call``. The 60-second budget spans that sequence
rather than one tool invocation, so the time available for server-side work is
correspondingly smaller.

The warning threshold is set at 45 seconds. A server measured at 50 seconds is
not passing; it is one slow dependency away from HTTP 424.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register

HARD_LIMIT_S = 60.0
WARN_AT_S = 45.0


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = min(len(ordered) - 1, int(round(pct * (len(ordered) - 1))))
    return ordered[index]


@register
class LatencyRule(Rule):
    id = "latency-p95"
    title = "Operations complete inside the 60-second timeout"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("timings",)

    def check(self, ev: Evidence) -> Finding:
        list_times = ev.latencies("tools/list")
        call_times = ev.latencies("tools/call")
        measured = list_times + call_times

        if not measured:
            return self.skipped("no successful timed operations to measure")

        p95 = _percentile(measured, 0.95)
        worst = max(measured)
        over_hard = [t for t in measured if t >= HARD_LIMIT_S]

        summary = (
            f"p95 {p95:.1f}s across {len(measured)} samples "
            f"(tools/list {len(list_times)}, tools/call {len(call_times)})"
        )

        chain_note = (
            "Quick re-initializes per operation, so one user query costs initialize + "
            "notifications/initialized + tools/list + tools/call. The 60s budget covers "
            "that whole chain."
        )

        if over_hard or p95 >= HARD_LIMIT_S:
            return self.failed(
                summary,
                detail=[
                    f"{len(over_hard)} of {len(measured)} samples reached or exceeded "
                    f"{HARD_LIMIT_S:.0f}s; slowest was {worst:.1f}s.",
                    "Quick fails these with HTTP 424.",
                    "",
                    chain_note,
                ],
                remediation=(
                    "Bring the slowest path well under 60 seconds. If the work genuinely "
                    "takes longer, return a handle immediately and let the caller poll, "
                    "rather than holding the request open."
                ),
            )

        if p95 >= WARN_AT_S:
            return self.failed(
                summary,
                detail=[
                    f"Slowest sample {worst:.1f}s, against a hard limit of "
                    f"{HARD_LIMIT_S:.0f}s (HTTP 424).",
                    "Under 60s today, with very little margin.",
                    "",
                    chain_note,
                ],
                remediation=(
                    "Treat anything above 45s as failing under load. Profile the slowest "
                    "tool and its dependencies before this reaches production."
                ),
            )

        return self.passed(
            summary,
            [f"slowest sample {worst:.1f}s, limit {HARD_LIMIT_S:.0f}s"],
        )


@register
class LatencyWarnRule(Rule):
    """Reliability of repeated calls, distinct from latency.

    Amazon Quick performs no retries, so a server that is fast on average but
    intermittently unreliable fails in production while appearing healthy under
    benchmarking."""

    id = "retry-exposure"
    title = "Reliability, given that Quick never retries"
    severity = Severity.WARN
    doc_verified = True
    requires = ("timings",)

    def check(self, ev: Evidence) -> Finding:
        rate = ev.failure_rate("tools/list")
        samples = [t for t in ev.timings if t.operation == "tools/list"]

        if rate is None or not samples:
            return self.skipped("no repeated operations to measure a failure rate")

        failures = [t for t in samples if not t.ok]
        if not failures:
            return self.passed(
                f"0 failures across {len(samples)} calls",
                ["no flakes observed -- though absence over a small sample is weak evidence"],
            )

        return self.failed(
            f"{len(failures)} of {len(samples)} calls failed ({rate:.0%})",
            detail=[
                "AWS: \"Server connectivity issues result in immediate failure without",
                "retry attempts.\" There is no second attempt, so the observed",
                "failure rate is the rate at which end users encounter errors.",
                "",
                *[f"  {t.error}" for t in failures[:3] if t.error],
            ],
            remediation=(
                "Identify the source of the intermittency before connecting. "
                "Client-side retries that other MCP clients perform are not available."
            ),
        )
