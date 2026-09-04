# qs-preflight

**Will your MCP server work with Amazon Quick?** Find out in two seconds, with a citation for every finding — instead of after a failed connector and a support ticket.

```console
$ qs-preflight check https://game.spacemolt.com/mcp

  Amazon Quick MCP Preflight — 13 rules
  https://game.spacemolt.com/mcp

    ✗  BLOCKER tool-count            219 tools exposed, limit is 100  [measured]
           119 tools are past the cap, starting at subscribe_market:
           subscribe_market, faction_visit_room, station, get_battle_summary, ... (+113 more)

           AWS documents that the first 100 register and the rest are dropped.
           Measured against a live Amazon Quick account on 2026-08-27, that is not
           what happens: at 101 tools connector creation FAILS OUTRIGHT and nothing
           is registered. 100 works. 101 does not.
           → Reduce the exposed surface to 100 tools or fewer, or split the server
             into several connections grouped by capability.
           https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations

    ✗  WARN    tool-list-stability   tool list returned in a different order between fetches
    ✓  BLOCKER schema-draft          all 219 inputSchema definitions are Draft 7 or later
    ✓  BLOCKER transport             streamable HTTP
    ✓  WARN    tool-annotations      all 219 tools declare annotations
    …

  1 blocker, 1 warning, 6 passed, 5 skipped.  Exit 1.
```

That is a real, live, third-party MCP server. It is well built — valid schemas, annotations declared on every tool, correct transport. It still cannot connect to Amazon Quick, and nothing would have told its authors why.

---

## Install

```bash
uvx qs-preflight check https://mcp.example.com/mcp     # no install
pip install qs-preflight                                # or install it
```

Requires Python 3.11 or later.

## Why this exists

Amazon Quick can consume remote MCP servers, but it is a demanding client. AWS documents roughly fifteen constraints a server must satisfy: a 60-second hard timeout, a 100-tool cap, no retries, frozen tool lists, no custom headers, OAuth endpoints that must be publicly reachable even for a private server, root-only metadata discovery, Dynamic Client Registration as the only automatic registration path.

None of them is checked for you. Several fail silently, and one common failure is reported with an error message that points at the wrong cause.

`qs-preflight` checks them from outside, before you commit engineering time.

## Usage

```bash
qs-preflight check <url>                    # human-readable report
qs-preflight check <url> --json             # machine-readable
qs-preflight check <url> --markdown         # paste into a PR or ticket
qs-preflight check <url> --fail-on warn     # stricter CI
qs-preflight rules                          # list the rules this version checks
```

For a server that requires authorization, supply a token so the tool-level rules can run:

```bash
export QS_PREFLIGHT_TOKEN='...'             # preferred: stays out of shell history
qs-preflight check https://mcp.example.com
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No blockers |
| `1` | Blockers present, or warnings with `--fail-on warn` |
| `2` | The checker itself could not complete |

Point it at a server in CI and a change that pushes you past the 100-tool cap fails the build instead of production.

## Try it in ten seconds

A deliberately non-compliant MCP server ships with the package:

```bash
qs-preflight mock-server --violations tool-count,schema-draft &
qs-preflight check http://127.0.0.1:8931/mcp
```

`qs-preflight mock-server --list-violations` shows what else it can break.

## What it checks

| Rule | Severity | Checks | Source |
|---|---|---|---|
| `tool-count` | BLOCKER | Tool count within Amazon Quick's registration cap **[measured]** | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `transport` | BLOCKER | Remote HTTP transport, reachable by a managed service | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-prerequisites) |
| `schema-draft` | BLOCKER | Tool inputSchema is JSON Schema Draft 7 or later | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-troubleshooting-creation) |
| `latency-p95` | BLOCKER | Operations complete inside the 60-second timeout **[measured]** | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `oauth-discovery-path` | BLOCKER | Protected Resource Metadata is discoverable the way Quick looks for it **[measured]** | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `oauth-scopes` | BLOCKER | Protected Resource Metadata declares `scopes_supported` | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `oauth-reachability` | BLOCKER | OAuth endpoints resolve publicly | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `dcr-available` | WARN | Authorization server offers Dynamic Client Registration | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `retry-exposure` | WARN | Reliability, given that Quick never retries | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `tool-list-stability` | WARN | Tool list is stable between fetches **[measured]** | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `header-independence` | WARN | Server functions with standard headers only | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-limitations) |
| `tool-annotations` | WARN | Tools declare read/write intent rather than leaving Quick to guess **[measured]** | [spec](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) |
| `manual-checklist` | INFO | Prerequisites no external check can verify **[measured]** | [docs](https://docs.aws.amazon.com/quick/latest/userguide/mcp-integration.html#mcp-integration-prerequisites) |

Regenerate this table with `qs-preflight rules --markdown`.

## Rules marked [measured]

Most compatibility checkers implement what the documentation says. Five of these rules report what was **observed against a live Amazon Quick Enterprise account** on 2026-08-27, and in three cases observation and documentation disagree.

**The 100-tool cap does not truncate — it destroys the connector.** AWS states that a server exposing more than 100 tools will have "the first 100 registered". Measured:

| Tools exposed | Result |
|---|---|
| 12 | Connector active, all registered |
| 100 | Connector active, all registered |
| **101** | **Creation failed, none registered** |
| 142 | Creation failed, none registered |

One tool over the documented cap costs the entire integration, reported as `Creation failed` — an error AWS attributes to invalid schemas — against a server whose own logs record no fault.

**Amazon Quick requests path-inserted metadata first**, despite documentation stating that discovery "uses the server root path only" and that path-insertion "is not supported".

**Read and write intent is inferred from tool names.** An undocumented step in the connector wizard classifies every tool as Read or Write, and read-only operations named `*_audit` and `*_export` were classified as writes, requiring user approval on every invocation.

## Limitations

Stated plainly, because a checker that overstates its confidence is worse than none.

- **`latency-p95` times `tools/list`, not your tools.** Invoking an unfamiliar server's tools can have real side effects, so it is opt-in via `--call-tool`. A server that lists quickly but performs slow work can still exceed the 60-second limit.
- **Three prerequisites cannot be checked from outside** — Enterprise subscription, callback URI allow-listing, and VPC DNS resolver configuration. These are emitted as a checklist rather than silently omitted.
- **Findings are derived from documentation and from one account's observed behaviour.** Amazon Quick may differ by region, account, or over time. Each citation records the date it was verified.
- **Not yet tested:** whether Quick accepts metadata served only at the path-inserted location, whether it honours MCP tool annotations, and whether the console's Sync control refreshes a registered tool list.

## Adding a rule

One file in `src/qs_preflight/rules/`, one import line in `rules/__init__.py`:

```python
@register
class MyRule(Rule):
    id = "my-rule"
    title = "What this establishes"
    severity = Severity.WARN
    doc_verified = True          # set only after reading the cited document
    requires = ("tools",)        # missing evidence yields SKIP, never FAIL

    def check(self, ev: Evidence) -> Finding:
        return self.passed("looks fine")
```

Rules are pure functions of an `Evidence` object, so they are tested without a network:

```bash
pytest tests -q
```

The suite fails while any registered rule carries an unverified citation. That is deliberate: a compatibility checker whose own citations were guessed would refute its premise.

## License

MIT — see [LICENSE](LICENSE).
