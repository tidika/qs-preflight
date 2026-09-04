"""Transport reachability for a managed client.

Amazon Quick can reach remote HTTP servers only. A stdio MCP server is not a
misconfigured remote server but a different deployment model with no network
address: the client launches it as a child process and communicates over pipes.
A managed service has no host on which to spawn that process.

A BLOCKER from this rule therefore does not indicate a configuration error. The
server cannot connect in its present form, and converting it requires hosting,
public TLS, and an authorization model that a stdio server does not need because
the operating system provides the trust boundary.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register


@register
class TransportRule(Rule):
    id = "transport"
    title = "Remote HTTP transport, reachable by a managed service"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ()

    def check(self, ev: Evidence) -> Finding:
        if ev.transport == "stdio":
            return self.failed(
                "target is a stdio server, not a remote endpoint",
                detail=[
                    "Quick launches nothing and reaches only URLs. A stdio server has no",
                    "address to give it.",
                ],
                remediation=(
                    "Re-host the server behind a public HTTPS endpoint using streamable "
                    "HTTP. Budget for the parts stdio never needed: hosting, TLS, "
                    "authentication, and per-user isolation now that one process serves "
                    "many callers."
                ),
            )

        if ev.transport == "auth-required":
            return self.skipped(
                "server requires authorization — reachable, but the MCP handshake "
                "cannot be completed without credentials"
            )

        if ev.transport == "unreachable" or ev.initialize_error:
            return self.failed(
                "the MCP handshake did not complete",
                detail=[
                    f"initialize returned: {ev.initialize_error or 'no response'}",
                    "",
                    "Quick performs the same handshake before it registers anything, so a",
                    "server that cannot complete it cannot be connected.",
                ],
                remediation=(
                    "Confirm the endpoint path is right (commonly /mcp), that the server "
                    "speaks streamable HTTP, and that it answers `initialize` without "
                    "requiring headers Quick will never send."
                ),
            )

        if ev.transport == "sse":
            return self.failed(
                "server offers the superseded SSE transport only",
                detail=[
                    "AWS states HTTP streaming is preferred over Server-Sent Events.",
                    "This is likely to work today and is not a good place to stay.",
                ],
                remediation="Move to streamable HTTP, the current MCP remote transport.",
            )

        if ev.transport == "streamable-http":
            negotiated = ev.protocol_version or "unreported"
            return self.passed(
                "streamable HTTP",
                [f"protocol revision negotiated: {negotiated}"],
            )

        return self.failed(
            f"unsupported transport: {ev.transport or 'unknown'}",
            remediation="Expose the server over remote streamable HTTP.",
        )
