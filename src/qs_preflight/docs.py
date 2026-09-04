"""Citation registry.

Every rule points at an entry here. A URL lands in this file only after a human
opened it and confirmed it states the constraint the rule enforces, and the date
of that check is recorded next to a verbatim quote.

Anything still marked UNVERIFIED fails `tests/test_evidence_discipline.py`, and
so fails the build. That is deliberate: a compatibility checker whose citations
were guessed would refute its own premise.

Some entries additionally carry ``verified_against_quick``, meaning the behaviour
was observed against a live Amazon Quick account rather than read from
documentation. Where observation and documentation disagree, the observed
behaviour is recorded here and the rule reports it in preference.

Source page read 2026-08-24 and re-verified 2026-08-27. Note the product prose
now reads "Amazon Quick"; the /quicksuite/ path mirrors identical content.
"""

from __future__ import annotations

from dataclasses import dataclass

UNVERIFIED = "UNVERIFIED"

BASE = "https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html"

A_LIMITS = f"{BASE}#mcp-integration-limitations"
A_PREREQ = f"{BASE}#mcp-integration-prerequisites"
A_AUTH = f"{BASE}#mcp-integration-authentication"
A_CAPS = f"{BASE}#mcp-integration-capabilities"
A_CREATE = f"{BASE}#mcp-integration-troubleshooting-creation"
A_VPC = f"{BASE}#mcp-integration-troubleshooting-vpc"
A_ENTRA = f"{BASE}#mcp-integration-troubleshooting-entra"

MCP_SPEC = "https://modelcontextprotocol.io/specification/2026-07-28"


@dataclass(frozen=True)
class Citation:
    url: str
    retrieved: str  # YYYY-MM-DD the URL was opened and confirmed
    quote: str  # verbatim, so drift in the source page is detectable
    verified_against_quick: str = ""  # observed behaviour, where it differs from the documentation


CITATIONS: dict[str, Citation] = {
    "tool-count": Citation(
        A_LIMITS,
        "2026-08-24",
        "Amazon Quick supports a maximum of 100 tools per MCP server connection. "
        "If the MCP server exposes more than 100 tools, only the first 100 are registered.",
        verified_against_quick=(
            "Measured 2026-08-27 against a live Enterprise account: 12 tools and 100 "
            "tools both register and publish; 101 tools and 142 tools both fail "
            "connector creation entirely, registering zero. The documented silent "
            "truncation to the first 100 was not observed at any size."
        ),
    ),
    "latency-p95": Citation(
        A_LIMITS,
        "2026-08-24",
        "MCP operations have a fixed 60-second timeout. Operations that exceed this "
        "limit automatically fail with an HTTP 424 error.",
        verified_against_quick=(
            "Observed 2026-08-27: Quick re-initializes per operation, so a single user "
            "query costs initialize + notifications/initialized + tools/list + "
            "tools/call. The 60s budget spans that chain, not one tool invocation."
        ),
    ),
    "transport": Citation(
        A_PREREQ,
        "2026-08-24",
        "MCP integration supports remote servers only. HTTP streaming is preferred over "
        "Server-Sent Events (SSE). Local stdio connections are not supported.",
    ),
    "schema-draft": Citation(
        A_CREATE,
        "2026-08-24",
        "Amazon Quick validates each tool's inputSchema against JSON Schema Draft 7 or "
        "later during the publish phase. The most common cause is the deprecated Draft 3 "
        'syntax, where required is a boolean inside a property definition (for example, "required": true).',
    ),
    "retry-exposure": Citation(
        A_LIMITS,
        "2026-08-24",
        "Server connectivity issues result in immediate failure without retry attempts.",
    ),
    "tool-list-stability": Citation(
        A_LIMITS,
        "2026-08-24",
        "Tool lists remain static after initial registration. To pick up server-side tool "
        "changes, you must delete the integration and recreate it.",
        verified_against_quick=(
            "Untested. The console exposes a Sync button on the connector, which may or "
            "may not refresh the tool list. The documented delete-and-recreate remedy is "
            "reported as AWS states it, not as verified."
        ),
    ),
    "oauth-discovery-path": Citation(
        A_LIMITS,
        "2026-08-24",
        "Well-known URI discovery uses the server root path only. Path-specific metadata "
        "locations (path-insertion discovery) are not supported.",
        verified_against_quick=(
            "Observed 2026-08-27: Quick requests the path-inserted location FIRST "
            "(/.well-known/oauth-protected-resource/mcp) and falls back to the root. "
            "Whether it would accept metadata served only at the path is untested."
        ),
    ),
    "oauth-scopes": Citation(
        A_LIMITS,
        "2026-08-24",
        "When the metadata does not specify supported scopes, Amazon Quick applies default "
        "scopes rather than omitting them. This behavior might cause authentication failures "
        "with servers that do not recognize the default scopes.",
    ),
    "dcr-available": Citation(
        A_LIMITS,
        "2026-08-24",
        "Only Dynamic Client Registration (DCR) is supported for automatic client "
        "registration. Client ID Metadata Documents are not supported.",
    ),
    "oauth-reachability": Citation(
        A_LIMITS,
        "2026-08-24",
        "For MCP servers that you reach through a VPC connection, the OAuth endpoints used "
        "by the MCP server must be reachable over the public internet. Private OAuth "
        "providers are not supported.",
    ),
    "header-independence": Citation(
        A_LIMITS,
        "2026-08-24",
        "Custom HTTP headers are not supported in MCP operations. Only standard system "
        "headers are transmitted.",
    ),
    "step-up-auth": Citation(
        A_LIMITS,
        "2026-08-24",
        "Step-up authorization is not supported. If an MCP server requires additional scopes "
        "after the initial authorization (HTTP 403 with insufficient_scope), then you must "
        "re-authorize the entire connection.",
    ),
    "resource-indicator": Citation(
        A_ENTRA,
        "2026-08-24",
        "Amazon Quick sends a resource parameter on OAuth requests as required by the MCP "
        "specification (RFC 8707). The Entra ID v2.0 endpoint rejects requests that include "
        "both a resource parameter and scope values.",
        verified_against_quick=(
            "Observed 2026-08-27: of three token requests in a single connector creation, "
            "two omitted the resource parameter entirely. The MCP specification makes it "
            "MUST-level and unconditional."
        ),
    ),
    # Not derived from AWS documentation. This rule originates in observed
    # behaviour; the citation references the MCP specification section defining
    # the annotations Amazon Quick was seen to disregard.
    "tool-annotations": Citation(
        f"{MCP_SPEC}/server/tools",
        "2026-08-27",
        "annotations: Optional properties describing tool behavior. [MCP specification, "
        "Tool data type]",
        verified_against_quick=(
            "Observed 2026-08-27: Quick sorts every tool into Read or Write in an "
            "undocumented wizard step, inferring from the tool name. Across 100 tools it "
            "classified adjust/audit/create/delete/export/reconcile/update as writes and "
            "list/lookup/search as reads, misclassifying read-only *_audit and *_export "
            "operations. Writes default to per-call user approval."
        ),
    ),
    "manual-checklist": Citation(
        A_PREREQ,
        "2026-08-24",
        "An Amazon Quick Enterprise subscription. [...] You must populate the DNS resolver "
        "endpoints field on the VPC connection with Route 53 Resolver inbound endpoint IP "
        "addresses. [...] Connector creation might fail if the Amazon Quick callback URI is "
        "not allow-listed by third-party providers.",
        verified_against_quick=(
            "Observed 2026-08-27: the console wizard also has two undocumented steps, "
            "Manage Write Permissions and Manage Read Permissions, and classifies every "
            "tool as Read or Write by inferring from its name -- misclassifying read-only "
            "operations such as *_audit and *_export as writes."
        ),
    ),
    # No statement about TLS or certificate validity appears anywhere on the AWS
    # page. Rather than cite something adjacent and pretend, this stays unverified
    # and must be re-cited against the MCP specification or cut before release.
    "tls-validity": Citation(UNVERIFIED, "", ""),
}


def url_for(rule_id: str) -> str:
    c = CITATIONS.get(rule_id)
    return c.url if c else UNVERIFIED


def quote_for(rule_id: str) -> str:
    c = CITATIONS.get(rule_id)
    return c.quote if c else ""


def measured(rule_id: str) -> str:
    c = CITATIONS.get(rule_id)
    return c.verified_against_quick if c else ""


def unverified_rule_ids() -> list[str]:
    return [rid for rid, c in CITATIONS.items() if c.url == UNVERIFIED]
