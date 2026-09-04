"""The network layer: one pass over the target, producing an Evidence bundle.

This is the only module that touches the network. Everything downstream is a
pure function of what it collects.

The probe imitates Amazon Quick rather than a current MCP client. Probing with
an up-to-date SDK would establish whether a server works with a modern client,
which is a different question. The sequence below reproduces behaviour observed
from Amazon Quick on 2026-08-27:

  * the classic handshake -- initialize, notifications/initialized, then work --
    with no `_meta` protocol fields, because Quick sends none
  * an unauthenticated probe first, hoping for a 401 that names the metadata
  * well-known discovery at the PATH-INSERTED location first, then the root,
    which is the opposite of what AWS documents
  * a request for `/.well-known/openid-configuration`, which AWS documents
    nowhere

Tools are not invoked by default. An unfamiliar server may expose destructive
operations, and a latency measurement does not justify the risk of triggering
one. Tool-call timing is opt-in through the ``call_tool`` argument.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from .evidence import (
    Evidence,
    HostResolution,
    OAuthDocs,
    TimingSample,
    TlsInfo,
    ToolRecord,
)

USER_AGENT = "qs-preflight/0.1 (+https://github.com/tidika/qs-preflight)"

# Quick does not advertise which MCP revision it speaks, and sends no
# protocolVersion in `_meta`. This is the revision claimed on initialize;
# override it if a target negotiates something else.
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

MAX_PAGES = 20  # guard against a server paginating forever


class _Client:
    """A JSON-RPC caller that copes with both streamable-HTTP response shapes."""

    def __init__(self, url: str, timeout: float, bearer_token: str | None = None):
        self.url = url
        self.timeout = timeout
        self.session_id: str | None = None
        # Held only in memory and only for the Authorization header. It is never
        # written to Evidence, so it cannot reach --json output, a log line, or
        # an error message.
        self._bearer = bearer_token
        self._id = 0
        self._http = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    def close(self) -> None:
        self._http.close()

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            # Both, because a server may answer either way.
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self._bearer:
            h["Authorization"] = f"Bearer {self._bearer}"
        return h

    def call(
        self, method: str, params: dict[str, Any] | None = None, notify: bool = False
    ) -> tuple[dict[str, Any] | None, float]:
        """Send one JSON-RPC message. Returns (result-or-error, elapsed seconds)."""
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notify:
            self._id += 1
            body["id"] = self._id
        if params is not None:
            body["params"] = params

        started = time.perf_counter()
        response = self._http.post(self.url, json=body, headers=self._headers())
        elapsed = time.perf_counter() - started

        sid = response.headers.get("mcp-session-id")
        if sid:
            self.session_id = sid

        if notify or not response.content:
            return None, elapsed
        return _parse_rpc(response), elapsed


def _parse_rpc(response: httpx.Response) -> dict[str, Any] | None:
    """Streamable HTTP answers with either plain JSON or an SSE frame."""
    text = response.text
    content_type = response.headers.get("content-type", "")

    if "text/event-stream" in content_type:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


_AUTH_SIGNALS = (
    "invalid_token",
    "unauthorized",
    "authentication required",
    "access denied",
    "forbidden",
    "-32001",  # commonly used by MCP servers for auth failures
)


def _looks_like_auth_failure(message: str, challenge_status: int | None) -> bool:
    """Determine whether a failure indicates missing credentials.

    A conformant protected server answers an unauthenticated probe with a 401 and
    valid OAuth metadata, then rejects ``initialize`` with an authorization
    error. Treating that as a broken transport would be a false positive.
    """
    if challenge_status in (401, 403):
        return True
    lowered = (message or "").lower()
    return any(signal in lowered for signal in _AUTH_SIGNALS)


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _collect_tls(url: str, timeout: float) -> TlsInfo | None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None

    host = parsed.hostname or ""
    port = parsed.port or 443
    info = TlsInfo()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
        info.valid = True
        not_after = cert.get("notAfter")
        if not_after:
            info.not_after = not_after
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            info.days_remaining = (expiry - datetime.now(timezone.utc)).days
        issuer = cert.get("issuer") or ()
        for part in issuer:
            for key, value in part:
                if key == "organizationName":
                    info.issuer = value
    except Exception as exc:
        info.valid = False
        info.error = f"{type(exc).__name__}: {exc}"
    return info


def _fetch_json(client: httpx.Client, url: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        r = client.get(url)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _discover_oauth(target: str, timeout: float) -> OAuthDocs:
    """Reproduce Quick's discovery sequence, in Quick's order."""
    docs = OAuthDocs()
    origin = _origin(target)
    path = urlparse(target).path.rstrip("/")

    with httpx.Client(
        timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:
        # 1. The unauthenticated probe. A well-behaved protected server answers
        #    401 with a WWW-Authenticate header naming its metadata document.
        try:
            r = client.get(target, headers={"Accept": "application/json"})
            docs.challenge_status = r.status_code
            challenge = r.headers.get("www-authenticate")
            if challenge:
                docs.www_authenticate = challenge
                for part in challenge.split(","):
                    part = part.strip()
                    if part.lower().startswith("resource_metadata="):
                        docs.resource_metadata_url = part.split("=", 1)[1].strip('"')
        except Exception as exc:
            docs.fetch_errors["challenge"] = f"{type(exc).__name__}: {exc}"

        # 2. Path-insertion first, exactly as Quick was observed to do, then root.
        if path:
            doc, err = _fetch_json(
                client, f"{origin}/.well-known/oauth-protected-resource{path}"
            )
            docs.protected_resource_path = doc
            if err:
                docs.fetch_errors["protected_resource_path"] = err

        doc, err = _fetch_json(client, f"{origin}/.well-known/oauth-protected-resource")
        docs.protected_resource_root = doc
        if err:
            docs.fetch_errors["protected_resource_root"] = err

        # 3. Authorization server metadata, from wherever the resource points.
        metadata = docs.metadata or {}
        servers = metadata.get("authorization_servers") or []
        issuer = servers[0] if servers else origin

        doc, err = _fetch_json(
            client, urljoin(issuer + "/", ".well-known/oauth-authorization-server")
        )
        docs.authorization_server = doc
        if err:
            docs.fetch_errors["authorization_server"] = err

        doc, err = _fetch_json(
            client, urljoin(issuer + "/", ".well-known/openid-configuration")
        )
        docs.openid_configuration = doc
        if err:
            docs.fetch_errors["openid_configuration"] = err

    return docs


def _resolve_oauth_hosts(oauth: OAuthDocs) -> list[HostResolution]:
    """Quick requires OAuth endpoints to be publicly reachable even when the
    MCP server itself is private: the server may sit behind a VPC while the
    identity provider may not."""
    endpoints: list[tuple[str, str]] = []
    server = oauth.authorization_server or oauth.openid_configuration or {}
    for role in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        value = server.get(role)
        if value:
            endpoints.append((role, value))

    seen: set[str] = set()
    results: list[HostResolution] = []
    for role, url in endpoints:
        host = urlparse(url).hostname
        if not host or host in seen:
            continue
        seen.add(host)
        entry = HostResolution(hostname=host, role=role)
        try:
            infos = socket.getaddrinfo(host, None)
            entry.addresses = sorted({i[4][0] for i in infos})
            entry.is_private = any(_is_private(a) for a in entry.addresses)
        except Exception as exc:
            entry.resolve_error = f"{type(exc).__name__}: {exc}"
        results.append(entry)
    return results


def _read_tools(client: _Client, ev: Evidence) -> list[ToolRecord]:
    """Walk tools/list, following pagination the way the protocol allows."""
    collected: list[ToolRecord] = []
    cursor: str | None = None
    pages = 0

    while pages < MAX_PAGES:
        params = {"cursor": cursor} if cursor else {}
        payload, elapsed = client.call("tools/list", params)
        ev.timings.append(
            TimingSample("tools/list", elapsed, ok=bool(payload and "result" in (payload or {})))
        )
        pages += 1

        if not payload or "result" not in payload:
            error = (payload or {}).get("error", "no result")
            ev.probe_errors["tools/list"] = json.dumps(error)[:300]
            break

        result = payload["result"]
        for raw in result.get("tools", []):
            collected.append(
                ToolRecord(
                    name=raw.get("name", ""),
                    description=raw.get("description", "") or "",
                    input_schema=raw.get("inputSchema") or {},
                    annotations=raw.get("annotations") or {},
                )
            )

        cursor = result.get("nextCursor")
        if not cursor:
            break

    ev.pages_fetched = pages
    ev.paginated = pages > 1
    return collected


def probe(
    target: str,
    *,
    timeout: float = 65.0,
    samples: int = 3,
    call_tool: str | None = None,
    protocol_version: str = DEFAULT_PROTOCOL_VERSION,
    bearer_token: str | None = None,
) -> Evidence:
    """Collect everything the rules need, in one pass over the network."""
    ev = Evidence(target=target, scheme=urlparse(target).scheme)

    if ev.scheme not in ("http", "https"):
        ev.transport = "stdio" if not ev.scheme else "unsupported"
        ev.probe_errors["target"] = (
            f"not an HTTP(S) URL: {target!r}. Amazon Quick supports remote servers "
            "only -- a stdio server has no address to connect to."
        )
        return ev

    ev.tls = _collect_tls(target, timeout=min(timeout, 15.0))
    ev.oauth = _discover_oauth(target, timeout=min(timeout, 20.0))
    ev.oauth_hosts = _resolve_oauth_hosts(ev.oauth)

    client = _Client(target, timeout, bearer_token=bearer_token)
    try:
        payload, _ = client.call(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "qs-preflight", "version": "0.1.0"},
            },
        )
        if not payload or "result" not in payload:
            ev.initialize_error = json.dumps((payload or {}).get("error", "no response"))[:300]
            challenge = ev.oauth.challenge_status if ev.oauth else None

            if _looks_like_auth_failure(ev.initialize_error, challenge):
                # The server is functioning; access was refused for lack of
                # credentials. Rules requiring a tool list will SKIP for want of
                # evidence. No probe error is recorded, since the target is not
                # at fault, and the run does not exit 2.
                ev.auth_required = True
                ev.transport = "auth-required"
            else:
                ev.probe_errors["initialize"] = ev.initialize_error
                ev.transport = "unreachable"
            return ev

        ev.authenticated = bool(bearer_token)

        result = payload["result"]
        ev.transport = "streamable-http"
        ev.protocol_version = result.get("protocolVersion")
        ev.server_info = result.get("serverInfo") or {}
        ev.server_capabilities = result.get("capabilities") or {}

        client.call("notifications/initialized", {}, notify=True)

        ev.tools = _read_tools(client, ev)

        # Second fetch, for the tool-list-stability rule.
        second = _read_tools(client, Evidence(target=target))
        ev.tools_second_fetch = [t.name for t in second]

        # Extra tools/list samples give latency and flake-rate a real p95 rather
        # than one lucky reading.
        for _ in range(max(0, samples - 1)):
            payload, elapsed = client.call("tools/list", {})
            ev.timings.append(
                TimingSample("tools/list", elapsed, ok=bool(payload and "result" in payload))
            )

        # Opt-in only. See the module docstring.
        if call_tool:
            for _ in range(samples):
                payload, elapsed = client.call(
                    "tools/call", {"name": call_tool, "arguments": {}}
                )
                ev.timings.append(
                    TimingSample(
                        "tools/call", elapsed, ok=bool(payload and "result" in payload)
                    )
                )
    except Exception as exc:
        ev.probe_errors["probe"] = f"{type(exc).__name__}: {exc}"
    finally:
        client.close()

    return ev
