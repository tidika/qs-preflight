"""Public resolvability of OAuth endpoints.

An MCP server may be private and reached through an Amazon Quick VPC connection.
Its authorization server may not: AWS states that "the OAuth endpoints used by
the MCP server must be reachable over the public internet... Private OAuth
providers are not supported."

A private server behind a private identity provider is a common architecture and
is not supported. Nothing in the MCP specification requires a publicly reachable
authorization server; this constraint originates with Amazon Quick.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register


@register
class OAuthReachabilityRule(Rule):
    id = "oauth-reachability"
    title = "OAuth endpoints resolve publicly"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("oauth_hosts",)

    def check(self, ev: Evidence) -> Finding:
        private = [h for h in ev.oauth_hosts if h.is_private]
        unresolved = [h for h in ev.oauth_hosts if h.resolve_error]
        public = [h for h in ev.oauth_hosts if not h.is_private and not h.resolve_error]

        if private:
            return self.failed(
                f"{len(private)} OAuth endpoint host(s) resolve to private addresses",
                detail=[
                    *[
                        f"{h.role}: {h.hostname} -> {', '.join(h.addresses)}"
                        for h in private
                    ],
                    "",
                    "Your MCP server may be private and reached over a VPC connection.",
                    "Its identity provider may not be. Private OAuth providers are",
                    "unsupported, and this is the failure most people do not see coming.",
                ],
                remediation=(
                    "Expose the authorization and token endpoints on the public internet, "
                    "or move to an identity provider that already is. The MCP server "
                    "itself can stay private."
                ),
            )

        if unresolved:
            return self.failed(
                f"{len(unresolved)} OAuth endpoint host(s) did not resolve",
                detail=[
                    *[f"{h.role}: {h.hostname} — {h.resolve_error}" for h in unresolved],
                    "",
                    "A hostname that does not resolve from here will not resolve from",
                    "Quick either, unless it is internal-only — which is itself the",
                    "unsupported case.",
                ],
                remediation=(
                    "Confirm the authorization server hostnames are publicly resolvable. "
                    "If they are internal-only, that configuration cannot work with Quick."
                ),
            )

        if not public:
            return self.skipped("no OAuth endpoints discovered to resolve")

        return self.passed(
            f"{len(public)} OAuth endpoint host(s) resolve publicly",
            [f"{h.role}: {h.hostname}" for h in public],
        )
