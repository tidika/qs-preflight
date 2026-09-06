"""Evidence bundle: everything gathered from the target in a single pass.

The whole design turns on this. The probe touches the network once and fills
this structure; every rule is then a pure function of it. That buys:

  * a single round trip rather than one per rule
  * rules testable against recorded JSON, without a network or a live server
  * ``--json`` output that is a serialisation rather than a second implementation
  * latency and stability rules, which require repeated samples, collected once

A rule that needs to perform an HTTP call indicates a missing field on this
structure. Such a field should be added here and populated by the probe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolRecord:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class TimingSample:
    operation: str  # "tools/list" | "tools/call"
    elapsed_s: float
    ok: bool
    error: str | None = None


@dataclass
class OAuthDocs:
    """Metadata fetched the way Amazon Quick fetches it.

    Observed on the wire 2026-08-27: Quick requests the *path-inserted*
    location first and falls back to the server root, despite AWS documenting
    that "path-insertion discovery is not supported". Capturing both lets a
    rule show which location answered rather than assert what should happen.

    Quick also probes `/.well-known/openid-configuration`, which AWS documents
    nowhere but the MCP specification requires clients to support.
    """

    challenge_status: int | None = None  # status of the unauthenticated probe
    www_authenticate: str | None = None  # the 401 challenge header, if any
    resource_metadata_url: str | None = None  # parsed out of that header

    protected_resource_path: dict[str, Any] | None = None
    protected_resource_root: dict[str, Any] | None = None
    authorization_server: dict[str, Any] | None = None
    openid_configuration: dict[str, Any] | None = None

    fetch_errors: dict[str, str] = field(default_factory=dict)
    # True when discovery failed at the transport layer rather than
    # returning a 404. An unreachable document is not an absent one.
    transport_failed: bool = False

    @property
    def metadata(self) -> dict[str, Any] | None:
        """Whichever protected resource document actually answered."""
        return self.protected_resource_root or self.protected_resource_path


@dataclass
class HostResolution:
    hostname: str
    role: str = ""  # "authorization_endpoint", "token_endpoint", ...
    addresses: list[str] = field(default_factory=list)
    is_private: bool = False
    resolve_error: str | None = None


@dataclass
class TlsInfo:
    valid: bool = False
    not_after: str | None = None
    days_remaining: int | None = None
    issuer: str | None = None
    error: str | None = None


@dataclass
class Evidence:
    target: str
    scheme: str = ""

    # Transport and handshake
    transport: str | None = None  # "streamable-http" | "sse" | "unreachable"
    protocol_version: str | None = None  # what the server negotiated
    server_info: dict[str, Any] = field(default_factory=dict)
    server_capabilities: dict[str, Any] = field(default_factory=dict)
    initialize_error: str | None = None

    # True when the server responded correctly but denied access for want of
    # a token. Distinguishing this from "unreachable" is important: most
    # enterprise MCP servers require authorization, and reporting them as having
    # a broken transport would be a false positive.
    auth_required: bool = False
    authenticated: bool = False

    # Tools
    tools: list[ToolRecord] = field(default_factory=list)
    tools_second_fetch: list[str] = field(default_factory=list)
    paginated: bool = False
    pages_fetched: int = 0

    # Timing and reliability
    timings: list[TimingSample] = field(default_factory=list)

    # Authorization
    oauth: OAuthDocs | None = None
    oauth_hosts: list[HostResolution] = field(default_factory=list)

    tls: TlsInfo | None = None

    # Anything the probe could not complete.
    probe_errors: dict[str, str] = field(default_factory=dict)

    # Set when the target could not be contacted at all: DNS failure, refused
    # connection, timeout, or an egress proxy refusing the request. Distinct
    # from a server that answered and was found wanting. Rules must not draw
    # conclusions from evidence that was never collected, so this short-circuits
    # the run into a single inconclusive result rather than reporting empty
    # evidence as absent metadata and an unsupported transport.
    network_error: str | None = None

    def has(self, key: str) -> bool:
        """Did the probe actually gather this? Drives `Rule.requires` -> SKIP."""
        value = getattr(self, key, None)
        if value is None:
            return False
        if isinstance(value, (list, dict)) and not value:
            return False
        return True

    def latencies(self, operation: str) -> list[float]:
        return [t.elapsed_s for t in self.timings if t.operation == operation and t.ok]

    def failure_rate(self, operation: str) -> float | None:
        samples = [t for t in self.timings if t.operation == operation]
        if not samples:
            return None
        return sum(1 for t in samples if not t.ok) / len(samples)
