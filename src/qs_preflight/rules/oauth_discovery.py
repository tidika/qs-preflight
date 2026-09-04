"""Discoverability of Protected Resource Metadata.

AWS states that discovery "uses the server root path only" and that
path-insertion discovery "is not supported".

Observation of Amazon Quick on 2026-08-27 showed a more nuanced behaviour. On
every discovery attempt it requested the path-inserted location first and fell
back to the server root::

    GET /.well-known/oauth-protected-resource/mcp   -> 404
    GET /.well-known/oauth-protected-resource       -> 200

The documented root-only behaviour therefore describes the fallback rather than
the complete sequence. Whether Amazon Quick would accept metadata served only at
the path-inserted location remains untested, so this rule reports against the
documented behaviour, which is the safer position for a caller to rely on.

Separately, AWS documents that a 401 response carrying a ``WWW-Authenticate``
header with a ``resource_metadata`` URL takes precedence, and that well-known
discovery is used only when that header is absent.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register


@register
class OAuthDiscoveryPathRule(Rule):
    id = "oauth-discovery-path"
    title = "Protected Resource Metadata is discoverable the way Quick looks for it"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("oauth",)

    def check(self, ev: Evidence) -> Finding:
        oauth = ev.oauth
        assert oauth is not None  # guaranteed by `requires`

        at_root = oauth.protected_resource_root is not None
        at_path = oauth.protected_resource_path is not None
        challenge = oauth.www_authenticate

        # An unprotected server is a legitimate configuration, not a failure.
        if not at_root and not at_path and not challenge:
            if oauth.challenge_status in (200, 202, 400, 406):
                return self.skipped(
                    "server does not appear to require authorization "
                    f"(unauthenticated probe returned {oauth.challenge_status}) — "
                    "no OAuth metadata to discover"
                )
            return self.failed(
                "no Protected Resource Metadata found at any location",
                detail=[
                    "Checked the path-inserted location and the server root, and no 401",
                    "challenge named one either.",
                    "",
                    "The MCP specification makes Protected Resource Metadata mandatory for",
                    "protected servers: \"MCP servers MUST implement OAuth 2.0 Protected",
                    "Resource Metadata\".",
                ],
                remediation=(
                    "Serve the document at /.well-known/oauth-protected-resource on the "
                    "server root, and return a 401 with a WWW-Authenticate header naming it."
                ),
            )

        if at_root:
            detail = ["found at /.well-known/oauth-protected-resource (the server root)"]
            if challenge:
                detail.append("server also emits a 401 WWW-Authenticate challenge naming it")
            if at_path:
                detail.append(
                    "also served at the path-inserted location, which Quick requests first"
                )
            return self.passed("metadata discoverable at the server root", detail)

        # Path only. Amazon Quick requests this location first, so it may
        # function, but AWS commits to the root and acceptance of a path-only
        # document has not been demonstrated.
        detail = [
            "Metadata was found only at the path-inserted location, not at the server root.",
            "",
            "AWS: \"Well-known URI discovery uses the server root path only. Path-specific",
            "metadata locations (path-insertion discovery) are not supported.\"",
            "",
            "Observed 2026-08-27: Quick does request the path-inserted location first.",
            "Whether it accepts a document served only there is untested, so this is",
            "so this is reported against the documented behaviour.",
        ]
        if challenge:
            detail += [
                "",
                "Mitigating: the server emits a 401 challenge naming its metadata, which is",
                "the documented primary path and may carry the integration regardless.",
            ]

        return self.failed(
            "metadata served only at the path-inserted location",
            detail=detail,
            remediation=(
                "Also serve the document at /.well-known/oauth-protected-resource on the "
                "server root. Serving both costs nothing and removes the ambiguity."
            ),
        )
