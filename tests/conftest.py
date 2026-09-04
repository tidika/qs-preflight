"""Test fixtures.

Every rule is a pure function of an `Evidence` object, so rules are tested by
handing them a constructed one. No network, no live server, milliseconds per
test -- which is the payoff for separating collecting from judging.

The mock server is exercised separately in test_integration.py, since unit tests
over constructed evidence cannot establish that the probe itself works.
"""

from __future__ import annotations

from typing import Any

import pytest

from qs_preflight.evidence import (
    Evidence,
    HostResolution,
    OAuthDocs,
    TimingSample,
    ToolRecord,
)

# Named the way real servers name things, so a failure message reads like a real
# report rather than `tool_007`.
_VERBS = ["lookup", "search", "create", "update", "delete", "list", "audit",
          "adjust", "export", "reconcile"]
_ENTITIES = ["inventory", "sku", "warehouse", "batch", "purchase_order",
             "supplier", "shipment", "carrier", "pick_list", "putaway",
             "return_order", "invoice", "forecast", "cycle_count", "receiving"]

_READ_ONLY_DESCRIPTIONS = {
    "audit": "Return the change history for a record in {entity}.",
    "export": "Export {entity} in a downloadable format.",
    "lookup": "Fetch a single record from {entity} by identifier.",
    "search": "Search {entity} by free-text query.",
    "list": "Page through {entity}.",
}


def _schema(draft3: bool = False) -> dict[str, Any]:
    if draft3:
        return {
            "type": "object",
            "properties": {"id": {"type": "string", "required": True}},
        }
    return {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    }


def make_tools(count: int, *, draft3: bool = False, annotate: bool = False) -> list[ToolRecord]:
    tools: list[ToolRecord] = []
    for i in range(count):
        entity = _ENTITIES[(i // len(_VERBS)) % len(_ENTITIES)]
        verb = _VERBS[i % len(_VERBS)]
        template = _READ_ONLY_DESCRIPTIONS.get(verb, "Modify {entity}.")
        tools.append(
            ToolRecord(
                name=f"{entity}_{verb}",
                description=template.format(entity=entity),
                input_schema=_schema(draft3),
                annotations={"readOnlyHint": True} if annotate else {},
            )
        )
    return tools


def make_evidence(
    *,
    tool_count: int = 10,
    draft3: bool = False,
    annotate: bool = False,
    transport: str = "streamable-http",
    latencies: list[float] | None = None,
    failures: int = 0,
    scopes: list[str] | None = None,
    registration_endpoint: str | None = None,
    prm_at_root: bool = True,
    prm_at_path: bool = False,
    private_oauth_host: bool = False,
    **overrides: Any,
) -> Evidence:
    tools = make_tools(tool_count, draft3=draft3, annotate=annotate)

    timings = [
        TimingSample("tools/list", t, ok=True) for t in (latencies or [0.05, 0.06, 0.05])
    ]
    timings += [
        TimingSample("tools/list", 0.0, ok=False, error="connection reset")
        for _ in range(failures)
    ]

    prm: dict[str, Any] | None = {
        "resource": "https://example.com/mcp",
        "authorization_servers": ["https://auth.example.com"],
    }
    if scopes is not None:
        prm["scopes_supported"] = scopes

    auth_server: dict[str, Any] | None = None
    if registration_endpoint is not None or scopes is not None or prm_at_root:
        auth_server = {
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
        }
        if registration_endpoint:
            auth_server["registration_endpoint"] = registration_endpoint

    oauth = OAuthDocs(
        challenge_status=401,
        protected_resource_root=prm if prm_at_root else None,
        protected_resource_path=prm if prm_at_path else None,
        authorization_server=auth_server,
    )

    hosts = [
        HostResolution(
            hostname="auth.example.com",
            role="token_endpoint",
            addresses=["10.0.0.5"] if private_oauth_host else ["93.184.216.34"],
            is_private=private_oauth_host,
        )
    ]

    ev = Evidence(
        target="https://mcp.example.com/mcp",
        scheme="https",
        transport=transport,
        protocol_version="2025-06-18",
        tools=tools,
        tools_second_fetch=[t.name for t in tools],
        timings=timings,
        oauth=oauth,
        oauth_hosts=hosts,
    )
    for key, value in overrides.items():
        setattr(ev, key, value)
    return ev


@pytest.fixture
def evidence():
    return make_evidence
