"""Prerequisites that cannot be verified from outside the account.

Every other rule answers its question by inspecting the server. The items below
depend on the AWS account, the identity provider's configuration, and a console
workflow, none of which is observable from a network probe.

Reporting them rather than omitting them is deliberate: a report of "12 passed"
that says nothing about unmet prerequisites would be misleading by omission.

The status is SKIP because no evaluation took place, which also excludes the rule
from the exit code. An informational checklist must not fail a build.

Three items derive from observation on 2026-08-27 rather than from published
documentation.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity, Status
from .base import Rule, register

CHECKLIST = [
    "[ ] Amazon Quick **Enterprise** subscription. MCP integration requires it; "
    "lower tiers do not offer the connector at all.",
    "",
    "[ ] Quick's callback URI allow-listed at your OAuth provider. AWS: \"Connector "
    "creation might fail if the Amazon Quick callback URI is not allow-listed by "
    "third-party providers.\"",
    "",
    "[ ] If connecting over a VPC: **DNS resolver endpoints** populated on the VPC "
    "connection with Route 53 Resolver inbound endpoint IPs. Quick does not use the "
    "default VPC DNS resolver, and without these the hostname will not resolve.",
    "",
    "[ ] If connecting over a VPC: route tables, network ACLs and security groups allow "
    "traffic from the connection's subnets to your server.",
    "",
    "--- undocumented; observed against a live account on 2026-08-27 ---",
    "",
    "[ ] Expect a five-step wizard: Connect, Authenticate, **Manage Write Permissions**, "
    "**Manage Read Permissions**, Publish. The two permission steps appear in no AWS "
    "documentation.",
    "",
    "[ ] There is no 'No authentication' option in the console, despite AWS documenting "
    "one in three places. The credential-free path is User authentication with Auth "
    "configuration set to 'Default OAuth app'.",
    "",
    "[ ] Review Quick's read/write classification of every tool before publishing. It is "
    "inferred from tool names and misclassifies read-only operations — see the "
    "tool-annotations finding.",
]


@register
class ManualChecklistRule(Rule):
    id = "manual-checklist"
    title = "Prerequisites no external check can verify"
    severity = Severity.INFO
    doc_verified = True
    requires = ()

    def check(self, ev: Evidence) -> Finding:
        return self._finding(
            Status.SKIP,
            "7 prerequisites to confirm by hand",
            detail=CHECKLIST,
        )
