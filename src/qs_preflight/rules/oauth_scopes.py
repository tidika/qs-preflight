"""Declaration of ``scopes_supported`` in Protected Resource Metadata.

A conformant server can fail this rule, and the reason is worth stating
precisely.

The MCP specification defines two mechanisms for a client to determine which
scopes to request, in priority order: the ``scope`` parameter of the 401
``WWW-Authenticate`` challenge, then ``scopes_supported`` from the metadata
document. It also defines the behaviour when the field is absent, directing
clients to omit the ``scope`` parameter entirely so that the authorization server
applies its own defaults.

Amazon Quick disables both mechanisms. It does not read the ``scope`` parameter
from the initial 401 challenge, and when ``scopes_supported`` is absent it
applies default scopes of its own rather than omitting the parameter.

The resulting request presents scopes the authorization server has not defined,
which it rejects. The failure surfaces as an authentication error, giving no
indication that the cause is an omitted optional field in a metadata document.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register


@register
class OAuthScopesRule(Rule):
    id = "oauth-scopes"
    title = "Protected Resource Metadata declares scopes_supported"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("oauth",)

    def check(self, ev: Evidence) -> Finding:
        oauth = ev.oauth
        assert oauth is not None

        metadata = oauth.metadata
        if metadata is None:
            return self.skipped(
                "no Protected Resource Metadata retrieved — see oauth-discovery-path"
            )

        scopes = metadata.get("scopes_supported")

        if isinstance(scopes, list) and scopes:
            return self.passed(
                f"scopes_supported declares {len(scopes)} scope(s)",
                [", ".join(str(s) for s in scopes[:8])],
            )

        detail = [
            "The metadata document omits scopes_supported.",
            "",
            "This is legal. The MCP specification plans for it: a client should omit the",
            "scope parameter entirely when scopes_supported is undefined, and let the",
            "authorization server apply its own defaults.",
            "",
            "Quick does the opposite. It applies default scopes of its own, and it also",
            "ignores the scope parameter on your 401 challenge — so both of the",
            "specification's fallbacks are unavailable.",
            "",
            "Expect an authentication failure whose message points at tokens, not at this.",
        ]
        if oauth.www_authenticate and "scope=" in oauth.www_authenticate:
            detail += [
                "",
                "Note: your server DOES advertise scopes on its 401 challenge, which is",
                "exactly what the specification recommends. Quick will not read it.",
            ]

        return self.failed(
            "scopes_supported is absent from Protected Resource Metadata",
            detail=detail,
            remediation=(
                "Declare scopes_supported explicitly in the metadata document, listing the "
                "minimal set needed for basic functionality — even though nothing in the "
                "specification requires you to."
            ),
        )
