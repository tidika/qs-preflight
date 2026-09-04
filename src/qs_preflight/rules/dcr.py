"""Availability of Dynamic Client Registration.

Amazon Quick is a managed, multi-tenant service and cannot be registered by hand
within each customer's identity provider. It therefore either registers itself
through Dynamic Client Registration or requires a client identifier and secret to
be configured manually.

The severity is WARN rather than BLOCKER because AWS documents the manual
fallback: "If the authorization server does not support DCR, then you must
manually provide credentials." Absent DCR costs convenience, not the integration.
Reporting it as a blocker would be a false positive.

The direction of travel is relevant. The current MCP specification states that
authorization servers and clients SHOULD support Client ID Metadata Documents,
and that Dynamic Client Registration "is deprecated and retained for backwards
compatibility". Amazon Quick supports only Dynamic Client Registration and states
that Client ID Metadata Documents are not supported, so authorization servers
built to the current specification are increasingly likely to require manual
credential configuration.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register


@register
class DcrAvailableRule(Rule):
    id = "dcr-available"
    title = "Authorization server offers Dynamic Client Registration"
    severity = Severity.WARN
    doc_verified = True
    requires = ("oauth",)

    def check(self, ev: Evidence) -> Finding:
        oauth = ev.oauth
        assert oauth is not None

        server = oauth.authorization_server or oauth.openid_configuration
        if server is None:
            if oauth.metadata is None:
                return self.skipped(
                    "no authorization server metadata retrieved — server may not require auth"
                )
            return self.skipped(
                "Protected Resource Metadata was found but authorization server metadata "
                "could not be fetched"
            )

        endpoint = server.get("registration_endpoint")
        if endpoint:
            return self.passed(
                "registration_endpoint present — Quick can self-register",
                [
                    str(endpoint),
                    "note: MCP now deprecates DCR in favour of Client ID Metadata "
                    "Documents, which Quick does not support. Keeping DCR available is "
                    "what keeps Quick working.",
                ],
            )

        return self.failed(
            "authorization server advertises no registration_endpoint",
            detail=[
                "Quick cannot register itself, so you must configure a client id and",
                "secret by hand in the console. The integration still works.",
                "",
                "AWS supports only DCR for automatic registration and explicitly does not",
                "support Client ID Metadata Documents — which the current MCP",
                "specification recommends, while deprecating DCR.",
            ],
            remediation=(
                "Either enable Dynamic Client Registration on the authorization server, or "
                "plan to configure credentials manually and document that for whoever "
                "sets up the connector."
            ),
        )
