"""Tool count against Amazon Quick's registration cap.

AWS documents silent truncation: "If the MCP server exposes more than 100 tools,
only the first 100 are registered." Testing against a live Amazon Quick
Enterprise account on 2026-08-27 produced different behaviour:

    12 tools  -> connector active, all registered
    100 tools -> connector active, all registered
    101 tools -> creation failed, none registered
    142 tools -> creation failed, none registered

Exceeding the documented cap by a single tool does not cost one tool. It causes
the entire integration to fail, reported with an error message AWS attributes to
invalid schemas, against a server whose own logs record no fault.

This rule therefore reports the observed behaviour rather than the documented
behaviour, and marks the finding as measured.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register

TOOL_LIMIT = 100
_PREVIEW = 6

# A grouping is only reported when several tools share a prefix. Servers that do
# not use an `entity_verb` naming convention would otherwise produce meaningless
# fragments, which is worse than reporting no grouping at all.
_MIN_GROUP_MEMBERS = 3


def _capability_groups(names: list[str]) -> list[str]:
    """Prefixes shared by enough tools to represent a coherent capability.

    Servers frequently group tools by entity, in which case an overflow past the
    cap removes complete capabilities rather than an arbitrary subset. Naming
    those capabilities is more actionable than reporting a count.
    """
    counts: dict[str, int] = {}
    for name in names:
        if "_" not in name:
            continue
        prefix = name.rsplit("_", 1)[0]
        counts[prefix] = counts.get(prefix, 0) + 1
    return sorted(p for p, n in counts.items() if n >= _MIN_GROUP_MEMBERS)


@register
class ToolCountRule(Rule):
    id = "tool-count"
    title = "Tool count within Amazon Quick's registration cap"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("tools",)

    def check(self, ev: Evidence) -> Finding:
        names = [t.name for t in ev.tools]
        total = len(names)

        if total <= TOOL_LIMIT:
            return self.passed(
                f"{total} tools exposed, limit is {TOOL_LIMIT}",
                [f"{TOOL_LIMIT - total} tools of headroom remaining"],
            )

        excess = names[TOOL_LIMIT:]
        preview = ", ".join(excess[:_PREVIEW])
        if len(excess) > _PREVIEW:
            preview += f", ... (+{len(excess) - _PREVIEW} more)"

        # Tools are usually grouped by entity, so the overflow is rarely a random
        # scattering -- it tends to be whole capabilities. Naming them is more
        # useful than counting them.
        groups = _capability_groups(excess)

        detail = [
            f"{len(excess)} tools are past the cap, starting at {excess[0]}:",
            preview,
            "",
            "AWS documents that the first 100 register and the rest are dropped.",
            "Measured against a live Amazon Quick account on 2026-08-27, that is not",
            "what happens: at 101 tools connector creation FAILS OUTRIGHT and nothing",
            "is registered. 100 works. 101 does not.",
        ]
        if groups:
            detail += [
                "",
                f"Whole capability groups fall past the cap: {', '.join(groups[:8])}",
            ]

        return self.failed(
            f"{total} tools exposed, limit is {TOOL_LIMIT}",
            detail=detail,
            remediation=(
                f"Reduce the exposed surface to {TOOL_LIMIT} tools or fewer, or split the "
                "server into several connections grouped by capability. Do not rely on "
                "ordering to decide what survives -- nothing survives."
            ),
        )
