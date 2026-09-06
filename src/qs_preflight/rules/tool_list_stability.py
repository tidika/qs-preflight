"""Stability of the advertised tool list between successive fetches.

Amazon Quick records the tool list at registration and does not refresh it. The
MCP specification treats a changing tool list as a supported feature, by way of
the ``listChanged`` capability and ``notifications/tools/list_changed``; Amazon
Quick does not consume those notifications.

The rule fetches ``tools/list`` twice and compares the results. Two identical
fetches are weak evidence, since a list that changes hourly will appear stable
across two calls seconds apart. A passing result therefore reports that no drift
was observed, not that the list is stable.

Custom connectors do not update on their own. AWS documents MCP Sync as the
remedy: opening the connector details page and choosing Sync refreshes the tool
list without recreating the integration. Built-in connectors sync automatically.
Triggering a sync initiates re-authorization, so a server that has begun
requiring scopes which were not granted originally will fail to sync.
"""

from __future__ import annotations

from .. import docs
from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register

# Deterministic ordering is required by the MCP specification, not by AWS. The
# ordering branch of this rule therefore cites the specification.
_SPEC_TOOLS = f"{docs.MCP_SPEC}/server/tools"

_PREVIEW = 5


@register
class ToolListStabilityRule(Rule):
    id = "tool-list-stability"
    title = "Tool list is stable between fetches"
    severity = Severity.WARN
    doc_verified = True
    requires = ("tools", "tools_second_fetch")

    def check(self, ev: Evidence) -> Finding:
        first = [t.name for t in ev.tools]
        second = ev.tools_second_fetch

        if first == second:
            detail = ["two consecutive fetches returned an identical list, in the same order"]
            if ev.server_capabilities.get("tools", {}).get("listChanged"):
                detail.append(
                    "note: the server declares the listChanged capability. Amazon Quick "
                    "does not consume list-change notifications, so a later change is "
                    "visible to it only when a connector owner triggers a manual sync."
                )
            return self.passed(f"{len(first)} tools, unchanged across two fetches", detail)

        added = [n for n in second if n not in first]
        removed = [n for n in first if n not in second]
        reordered = not added and not removed

        if reordered:
            return self.failed(
                "tool list returned in a different order between fetches",
                detail=[
                    "Same tools, different order. The MCP specification says servers "
                    "SHOULD return tools in a deterministic order.",
                    "Ordering instability suggests the list is assembled from an "
                    "unordered source, which tends to precede membership instability.",
                ],
                remediation="Return tools in a stable, deterministic order.",
                doc_url=_SPEC_TOOLS,
            )

        detail = []
        if added:
            detail.append(f"{len(added)} appeared: {', '.join(added[:_PREVIEW])}")
        if removed:
            detail.append(f"{len(removed)} disappeared: {', '.join(removed[:_PREVIEW])}")
        detail += [
            "",
            "Quick registers the list once and never refreshes it on its own. A list "
            "that moves will silently diverge from what Quick believes exists.",
        ]

        return self.failed(
            f"tool list changed between two fetches seconds apart",
            detail=detail,
            remediation=(
                "Make the exposed set deterministic. Where the list is intended to "
                "change, the connector owner must open the connector details page and "
                "choose Sync to pick the changes up. Note that a sync triggers "
                "re-authorization and will fail if the server has begun requiring scopes "
                "that were not granted originally."
            ),
        )
