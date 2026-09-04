"""Builds the mock MCP server on the official SDK.

Built on the ``mcp`` package's low-level ``Server`` rather than hand-written
JSON-RPC. The SDK provides the protocol -- transport, framing, initialize
handshake and error envelopes -- so the server is conformant by construction, and
only the payload is controlled here. That division matters: when Amazon Quick
rejects this server, the protocol layer cannot be the cause.
"""

from __future__ import annotations

from typing import Any

import mcp.types as types
from mcp.server import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings

from . import auth, catalogue, violations as vio
from .wire import WireLog

SERVER_NAME = "acme-warehouse"
SERVER_VERSION = "1.4.0"
MCP_PATH = "/mcp"


def _tools_for(active: set[str]) -> list[types.Tool]:
    count = catalogue.FULL_COUNT if "tool-count" in active else catalogue.CLEAN_COUNT
    draft3 = "schema-draft" in active

    out: list[types.Tool] = []
    for tool in catalogue.tools(count):
        schema: dict[str, Any] = tool.input_schema
        if draft3:
            schema = catalogue.to_draft3(schema)
        out.append(
            types.Tool(
                name=tool.name,
                description=tool.description,
                inputSchema=schema,
            )
        )
    return out


def _page(tools: list[types.Tool], cursor: str | None) -> tuple[list[types.Tool], str | None]:
    """Cursor pagination, exactly as MCP permits.

    Paginating ``tools/list`` is a documented and conformant part of the
    protocol. A client that stops at the first page would register 50 tools out
    of 142 rather than 100. AWS documentation does not mention pagination, so
    this fixture exists to exercise that case.
    """
    try:
        start = int(cursor) if cursor else 0
    except ValueError:
        start = 0

    page = tools[start : start + vio.PAGE_SIZE]
    nxt = start + vio.PAGE_SIZE
    return page, (str(nxt) if nxt < len(tools) else None)


def build_server(active: set[str]) -> Server:
    async def on_list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        tools = _tools_for(active)

        if "pagination" in active:
            page, next_cursor = _page(tools, params.cursor if params else None)
            return types.ListToolsResult(tools=page, nextCursor=next_cursor)

        return types.ListToolsResult(tools=tools)

    async def on_call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        known = {t.name for t in _tools_for(active)}
        if params.name not in known:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool: {params.name}")],
                isError=True,
            )
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=f"{params.name} completed. (mock server: no real system was touched)",
                )
            ]
        )

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        title="Acme Warehouse Operations",
        description="Warehouse, procurement and fulfilment operations.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_app(
    active: set[str],
    *,
    json_response: bool = False,
    public_url: str | None = None,
    wire_log: bool = False,
):
    """ASGI app for the mock server.

    DNS rebinding protection is disabled deliberately. The SDK enables it by
    default and validates the Host header against localhost, which is correct for
    a locally reached server but prevents this one from being reached through a
    public tunnel. Left enabled, every external request is rejected before any
    rule is evaluated, and the resulting failure does not resemble its cause.
    """
    server = build_server(active)
    extra = auth.routes(public_url) if public_url else None
    app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=json_response,
        custom_starlette_routes=extra,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
            allowed_hosts=["*"],
            allowed_origins=["*"],
        ),
    )
    # Wrapping the Starlette app rather than adding Starlette middleware keeps
    # the lifespan protocol intact, which the SDK's session manager depends on.
    return WireLog(app) if wire_log else app
