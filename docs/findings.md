# Observed behaviour of Amazon Quick's MCP client

Everything here was **observed**, not inferred. Each entry says what was seen, what
AWS's documentation says, and whether the finding is settled or still open.

Method: a spec-compliant MCP server built on the official `mcp` Python SDK (2.1.0),
exposed over a Cloudflare tunnel, connected to Amazon Quick from a real Enterprise
account. Server logs captured every request Quick made.

| | |
|---|---|
| Date | 2026-08-27 |
| Quick account | single account, single region — findings are not proven universal |
| Mock server | `mcp` SDK 2.1.0, low-level `Server`, streamable HTTP, stateless |
| Documentation compared against | [Amazon Quick MCP integration](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html), read 2026-08-24 and re-verified 2026-08-27 |

---

## CONFIRMED — contradicts AWS documentation

### F1. The documented three-way authentication choice is not what the console presents

> **Corrected 2026-08-27.** This finding originally claimed no credential-free path
> existed. That was wrong, and it was wrong because it was written after looking at
> only the top-level radio buttons. The correction is kept visible rather than
> silently edited — a checker that cites evidence has to hold itself to the same
> standard.

AWS documents a three-way choice in **three** separate places:

- Important callout: *"MCP servers that do not require authentication are also supported."*
- `#mcp-integration-authentication`, its own bolded subsection: *"**No authentication** — If the MCP server does not require authentication, no credentials are needed. Select this option for MCP servers that allow unauthenticated access."*
- `#mcp-integration-setup` step 6: *"Select the authentication method (user, service, or no authentication)."*

The console offers **two** top-level methods — User authentication and Service
authentication — with the credential-free path hidden one level down, in an
**Auth configuration** dropdown under User authentication:

| Method | Auth configuration | Credentials required |
|---|---|---|
| User authentication | `Default OAuth app` | none — *"No additional credentials are needed."* |
| User authentication | `Custom user based OAuth` | client id, secret, token URL, authorization URL, redirect URL |
| Service authentication | service OAuth | client id, secret, token URL |

**What is accurate:** there is no option labelled "No authentication", and the
documented flat three-way selection does not match a two-level UI. Someone following
step 6 literally will not find the choice it describes.

**What is still unknown:** whether `Default OAuth app` is the documented
"No authentication" mode under another name, or a genuine OAuth flow using a
Quick-owned client. Untested. See *Not yet tested*.

### F2. Quick attempts path-insertion discovery, first

AWS's Limitations section:

> "Well-known URI discovery uses the server root path only. Path-specific metadata
> locations (path-insertion discovery) are not supported."

Observed, on every one of three discovery rounds:

```
GET /.well-known/oauth-protected-resource/mcp   → 404   ← path-insertion, tried FIRST
GET /.well-known/oauth-protected-resource       → 200   ← root, the fallback
```

**Open sub-question:** we proved Quick *requests* the path-inserted location, not that
it would *accept* metadata served only there. Needs a run where the root URI 404s and
only the path URI answers.

### F3. Quick omits the RFC 8707 `resource` parameter on most token requests

AWS: *"Amazon Quick sends a `resource` parameter on OAuth requests as required by the
MCP specification (RFC 8707)."*

MCP specification, MUST-level and unconditional: *"**MUST** be included in both
authorization requests and token requests"* … *"MCP clients **MUST** send this
parameter regardless of whether authorization servers support it."*

Three token requests observed in a single connector creation:

| Source IP | `resource` | `scope` |
|---|---|---|
| 44.208.229.126 | **absent** | `mcp:tools` |
| 54.174.12.167 | **absent** | `mcp:tools` |
| 3.222.148.141 | present | `mcp:tools` |

**Consequence:** against an authorization server that binds tokens by audience, this
is an intermittent authentication failure — the hardest kind to diagnose.

---

## CONFIRMED — undocumented behaviour

### F4. The console wizard has two undocumented permission steps

Observed steps: **Connect → Authenticate → Manage Write Permissions → Manage Read
Permissions → Publish**.

The documented procedure goes from authentication straight to "Create and continue",
review, and share. Per-tool read/write permission granularity is not mentioned
anywhere on the page.

### F5. Quick injects its own `listTools` meta-tool

The failed connector exposed exactly one tool, which our server does not define:

| Tool | Type | Description |
|---|---|---|
| `listTools` | Read | "Lists all tools that are exposed by this MCP connector" |

### F6. Quick attempts OpenID Connect discovery

`GET /.well-known/openid-configuration` on every discovery round. Undocumented by AWS,
but specification-correct — MCP requires clients to support both RFC 8414 and OIDC
Discovery.

### F7. Discovery is repeated per component, from many source addresses

Requests arrived from at least five AWS IPs (`44.223.x`, `44.208.x`, `54.174.x`,
`3.222.x`, `52.54.x`), each repeating Protected Resource Metadata and authorization
server metadata fetches, and three separate token requests were issued for one
connector creation.

### F8. Quick reads and displays server-level metadata

Our server advertises `"Warehouse, procurement and fulfilment operations."` The console
showed `"Provides tools for Warehouse, procurement and fulfilment operations."` — Quick
consumes the server description and prefixes it.

---

### F11. Quick classifies tools as Read or Write by inference, and misclassifies read-only tools

Quick's connector wizard has an undocumented step that sorts every tool into **Write
Operations** or **Read Operations**, defaulting writes to *"Always ask — users approve
each tool before it runs, every time."*

Our server declared **no** MCP `annotations` — no `readOnlyHint`, no `destructiveHint`.
Quick therefore has nothing authoritative to go on, and infers from the tool name and
description. Of 12 tools it classified 7 as writes, including two that are read-only by
their own descriptions:

| Tool | Description we published | Quick's classification |
|---|---|---|
| `inventory_audit` | "**Return** the change history for a record in inventory records" | **Write** |
| `inventory_export` | "**Export** inventory records in a downloadable format" | **Write** |

Confirmed end to end in Quick Chat:

- *"Look up inventory record SKU-1042"* → `inventory_lookup` ran immediately, no prompt.
- *"Show me the audit history for inventory record SKU-1042"* → **"Requesting Action review — Allow Quick to perform inventory_audit"**, requiring explicit human approval.

**Consequence:** reading a change log requires a human to click approve, every time,
forever — because the word "audit" reads as dangerous to whatever classifier Quick uses.
Tool naming silently determines end-user friction, and nothing documents this.

**Open:** whether declaring MCP `annotations.readOnlyHint: true` overrides the inference.
If it does, the remedy is a one-line change and belongs in the rules. If it does not,
the classifier is unoverridable, which is a much harder problem for server authors.

### F12. Quick re-initializes on every operation

Method tally across one connector creation plus two user queries:

| Method | Count |
|---|---|
| `initialize` | 5 |
| `notifications/initialized` | 5 |
| `tools/list` | 4 |
| `tools/call` | 2 |

Each user query costs a fresh handshake — `initialize`, `notifications/initialized`,
`tools/list`, then `tools/call` — rather than reusing a session.

**Consequence for the 60-second budget:** the documented timeout covers a chain of four
round trips, not one tool invocation. A tool with 50 seconds of work has less headroom
than the published limit implies.

### F13. Quick does not send the protocol version the current MCP revision requires

Every request logged `protocolVersion=(no protocolVersion)`. The 2026-07-28 revision
requires `io.modelcontextprotocol/protocolVersion` in `_meta` on **every** request, and
says a request missing it "is malformed; the server **MUST** reject it with `-32602`".

Quick uses the older session-based handshake (`initialize` →
`notifications/initialized` → operations). The SDK accepts this for backwards
compatibility, so it is not fatal — but a server built strictly to the current revision
would reject every request Quick sends.

---

## OPEN — observed, not yet attributed

### F9. `Creation failed` with valid Draft 7 schemas, and zero tools registered

A server exposing **142 tools with valid Draft 7+ schemas** produced status
`Creation failed`, with none of its tools registered.

AWS attributes this message to invalid `inputSchema`: *"This error usually means that
one or more tool definitions in your MCP server's `tools/list` response contain an
invalid `inputSchema`."* The schemas were verified valid over the public URL before the
run, so that is **not** the cause here. The same opaque message covers at least one
other failure mode.

Note this is not truncation to 100. It is failure to register **anything**.

Candidate causes, none yet eliminated:
1. 142 tools causes hard failure rather than the documented silent truncation
2. Protocol revision mismatch (see F10)
3. SSE response framing
4. Something else

**Bisect, 2026-08-27.** Same tunnel, same service-authentication credentials, same code
path every time. Only the number of tools served changed:

| Tools served | Connector status | Tools registered |
|---|---|---|
| 12 | **Active** — published, invocations succeed | 12 |
| **100** | **Active** | **100** |
| **101** | **Creation failed** | **0** |
| 142 | Creation failed | 0 |

In every failing run the server logs were *clean*: `initialize`, `notifications/initialized`
and `tools/list` all returned 200, the full tool list was delivered, and no error was
raised on our side. The failure happens entirely inside Quick, after it has the list.

**That is the reason this project exists.** An operator watching their own logs during a
failed Quick integration sees a perfectly healthy server and no explanation at all.

Contrast with what AWS documents: *"If the MCP server exposes more than 100 tools, only
the first 100 are registered."* Observed behaviour is not partial registration. It is
total failure, reported with an error message AWS attributes to invalid schemas.

**The boundary is exactly the documented cap.** 100 tools registers cleanly and publishes;
101 destroys the connector. One tool over the limit is the difference between a working
integration and no integration at all.

**Reclassified: this is no longer an open question.** Promote to CONFIRMED —
contradicts AWS documentation. Four runs, one variable, a boundary landing precisely
where the documentation says the limit is.

**What this changes about the `tool-count` rule:** the remediation is not "you will
silently lose the tools past 100." It is "your connector will not be created at all."
Same severity, completely different consequence — and the tools named in the report are
not casualties to be mourned but the reason nothing works.

### F10. `GET /mcp` → 406 and `POST /mcp` → 400 — RESOLVED, benign

Wire logging identified both. They are Quick's **unauthenticated probes**, sent to
provoke a 401 that would reveal the auth metadata location:

```
GET  /mcp -> 406   accept: application/json
                   {"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}
POST /mcp -> 400   accept: application/json
                   Invalid Content-Type header
```

Our server does not require auth, so it answers 406/400 rather than 401, and Quick falls
back to well-known discovery. Nothing breaks.

Worth noting anyway: Quick's GET probe sends `Accept: application/json`. MCP's streamable
HTTP transport requires a client opening a GET stream to accept `text/event-stream`, so
any conformant server **must** reject it. Every spec-correct server will therefore log
errors during Quick connector creation that look alarming and are not.

---

## Not yet tested

- Whether Quick honours `tools/list` pagination (`nextCursor`)
- Whether truncation at 100 happens at all, and whether it warns
- The literal on-screen error text for a genuine Draft 3 schema failure
- What default scopes Quick applies when `scopes_supported` is absent
- Whether metadata served *only* at the path-inserted URI is accepted (F2)
- What `Default OAuth app` under User authentication actually does (F1). The mock's
  wire log reports whether an `Authorization` header arrives, so a single connector
  creation settles whether this is unauthenticated access under a different name or a
  real OAuth flow with a Quick-owned client.
