"""Wire-level logging, recording what a client actually sent.

Access logs record that a request was rejected but not its contents. When Amazon
Quick connector creation failed against a server with valid schemas, the access
log showed two ``400 Bad Request`` responses and nothing identifying the cause.

This middleware records, for every HTTP exchange:

  * the JSON-RPC method being called
  * the MCP protocol revision the client claims, from the `_meta` fields
  * whether an Authorization header was present
  * the response body whenever the status is 4xx or 5xx

This is diagnostic instrumentation for the test fixture, not part of the
checker itself.
"""

from __future__ import annotations

import json
from typing import Any

MAX_CAPTURE = 4096
PROTOCOL_KEY = "io.modelcontextprotocol/protocolVersion"


def _summarise_request(body: bytes) -> str:
    if not body:
        return "no body"
    try:
        payload: Any = json.loads(body)
    except Exception:
        return f"non-JSON body ({len(body)} bytes): {body[:200]!r}"

    items = payload if isinstance(payload, list) else [payload]
    parts = []
    for item in items:
        if not isinstance(item, dict):
            parts.append(f"non-object: {str(item)[:80]}")
            continue
        method = item.get("method", "(no method)")
        meta = (item.get("params") or {}).get("_meta") or {}
        version = meta.get(PROTOCOL_KEY, "(no protocolVersion)")
        parts.append(f"method={method} protocolVersion={version}")
    return "; ".join(parts)


class WireLog:
    """Raw ASGI middleware. Raw rather than Starlette's BaseHTTPMiddleware so
    that request and response bodies are both observable without interfering
    with streaming responses."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

        request_body = bytearray()

        async def receive_logging():
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                if len(request_body) < MAX_CAPTURE:
                    request_body.extend(chunk[: MAX_CAPTURE - len(request_body)])
            return message

        state: dict[str, Any] = {"status": None, "body": bytearray()}

        async def send_logging(message):
            if message.get("type") == "http.response.start":
                state["status"] = message.get("status")
            elif message.get("type") == "http.response.body":
                if state["status"] and state["status"] >= 400:
                    chunk = message.get("body", b"")
                    if len(state["body"]) < MAX_CAPTURE:
                        state["body"].extend(chunk[: MAX_CAPTURE - len(state["body"])])
            await send(message)

        await self.app(scope, receive_logging, send_logging)

        status = state["status"]
        auth = "yes" if headers.get("authorization") else "no"
        accept = headers.get("accept", "(none)")

        line = f"  [wire] {method} {path} -> {status}  auth={auth}"
        if method == "POST" and request_body:
            line += f"  {_summarise_request(bytes(request_body))}"
        if status and status >= 400:
            line += f"\n         accept: {accept}"
            if request_body:
                line += f"\n         request:  {bytes(request_body)[:600].decode(errors='replace')}"
            if state["body"]:
                line += f"\n         response: {bytes(state['body'])[:600].decode(errors='replace')}"
        print(line)
