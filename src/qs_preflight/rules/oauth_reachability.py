"""Reachability of OAuth endpoints.

By default, Amazon Quick reaches an authorization server over the public
internet, so an endpoint resolving only to a private address will fail.

That default can now be changed. Amazon Quick supports an auth-server VPC
connection, configured independently of the connection used for the MCP server
itself, which routes OAuth traffic through a VPC. A privately hosted
authorization server is therefore supported, provided that connection is
configured and its DNS resolver endpoints can resolve the hostname.

This rule reports a privately resolving endpoint because the default
configuration will not reach it, and states the remedy. It cannot determine from
outside whether an auth-server VPC connection has been configured.
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
                    "Amazon Quick reaches OAuth endpoints over the public internet unless",
                    "an auth-server VPC connection is configured on the integration. This",
                    "check cannot see that setting, so treat this as a prompt to confirm",
                    "it rather than a certain failure.",
                ],
                remediation=(
                    "Either expose the authorization and token endpoints on the public "
                    "internet, or configure an auth-server VPC connection on the "
                    "integration so that Amazon Quick reaches them through your VPC. That "
                    "connection is independent of the one used for the MCP server, and "
                    "its DNS resolver endpoints must resolve the authorization server "
                    "hostname."
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
