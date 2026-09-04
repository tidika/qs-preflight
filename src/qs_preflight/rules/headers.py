"""Dependence on custom HTTP headers.

Whether a server relies on a header cannot be determined by inspection from
outside. The MCP specification does, however, define a mechanism that is visible
in tool definitions: ``x-mcp-header`` marks a tool parameter to be mirrored into
an ``Mcp-Param-{name}`` HTTP header so that intermediaries can route on its value
without parsing the request body.

AWS states that only "standard system headers are transmitted". Whether Amazon
Quick treats ``Mcp-Param-*`` as standard is undocumented and has not been tested,
so this rule reports a WARN identifying the risk rather than a BLOCKER asserting
failure. If such headers are dropped, the request still arrives, but without the
value the tool depends on, and the resulting failure is silent.
"""

from __future__ import annotations

from typing import Any

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register

_PREVIEW = 5


def _header_params(schema: dict[str, Any]) -> list[str]:
    """Property names carrying an x-mcp-header annotation."""
    found = []
    for name, prop in (schema.get("properties") or {}).items():
        if isinstance(prop, dict) and prop.get("x-mcp-header"):
            found.append(f"{name} -> Mcp-Param-{prop['x-mcp-header']}")
    return found


@register
class HeaderIndependenceRule(Rule):
    id = "header-independence"
    title = "Server functions with standard headers only"
    severity = Severity.WARN
    doc_verified = True
    requires = ("tools",)

    def check(self, ev: Evidence) -> Finding:
        dependent: list[str] = []
        for tool in ev.tools:
            for mapping in _header_params(tool.input_schema):
                dependent.append(f"{tool.name}: {mapping}")

        if not dependent:
            return self.passed(
                f"no tool depends on custom headers across {len(ev.tools)} tools",
                ["no x-mcp-header annotations found in any inputSchema"],
            )

        return self.failed(
            f"{len(dependent)} tool parameter(s) rely on x-mcp-header mirroring",
            detail=[
                *dependent[:_PREVIEW],
                *([f"... and {len(dependent) - _PREVIEW} more"] if len(dependent) > _PREVIEW else []),
                "",
                "AWS: \"Custom HTTP headers are not supported in MCP operations. Only",
                "standard system headers are transmitted.\" Whether Mcp-Param-* headers",
                "count as standard is undocumented and untested.",
                "",
                "If they are dropped, the call still arrives — without the value your",
                "routing or backend selection depends on. That failure is silent.",
            ],
            remediation=(
                "Do not depend on header mirroring for correctness. Read these values from "
                "the tool arguments in the request body, which always arrive."
            ),
        )
