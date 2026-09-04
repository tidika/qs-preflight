# Contributing

## Setup

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest tests -q
```

## Adding a rule

A rule is one file in `src/qs_preflight/rules/` and one import line in
`rules/__init__.py`. Nothing else needs to change.

```python
from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register


@register
class ToolCountRule(Rule):
    id = "tool-count"
    title = "Tool count within Amazon Quick's registration cap"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("tools",)

    def check(self, ev: Evidence) -> Finding:
        total = len(ev.tools)
        if total <= 100:
            return self.passed(f"{total} tools exposed, limit is 100")
        return self.failed(
            f"{total} tools exposed, limit is 100",
            detail=[f"{total - 100} tools are past the cap"],
            remediation="Reduce the exposed surface to 100 tools or fewer.",
        )
```

Then add it to `rules/__init__.py`:

```python
from . import tool_count  # noqa: F401
```

## The four rules a rule must follow

**1. Cite a document, and read it first.** Add an entry to `docs.CITATIONS` with
the URL, the date it was read, and a verbatim quote of the passage that justifies
the check. Set `doc_verified = True` only after doing so. The test suite fails
while any registered rule carries an unverified citation.

The quote matters as much as the URL: it makes drift detectable when the source
page changes.

**2. Declare what evidence the rule needs.** `requires` names fields on
`Evidence`. Missing evidence produces SKIP with a stated reason, never FAIL.
Reporting an authorization failure against a server that requires no
authorization is a false positive, and one false positive undermines every other
finding in the report.

**3. Do no I/O.** A rule is a pure function of an `Evidence` object. If a rule
needs data the bundle does not carry, add a field to `Evidence` and populate it
in `probe.py`. This keeps the network cost at one pass regardless of how many
rules exist, and keeps rules testable without a server.

**4. Prefer a warning to a false blocker.** BLOCKER means the integration will
not work. If a documented fallback exists — as it does for Dynamic Client
Registration — the correct severity is WARN.

## Tests

Every rule needs a passing case and a failing case. Rules are tested against
constructed `Evidence`, so the tests need no network:

```python
def test_tool_count_green(evidence):
    assert ToolCountRule().check(evidence(tool_count=42)).status is Status.PASS


def test_tool_count_red(evidence):
    finding = ToolCountRule().check(evidence(tool_count=142))
    assert finding.status is Status.FAIL
    assert finding.is_blocking
```

`tests/conftest.py` provides the `evidence` factory. `tests/test_integration.py`
exercises the probe end to end against the bundled mock server; mark such tests
`@pytest.mark.slow`.

## The mock server

`src/qs_preflight/_mock/` is a deliberately non-compliant MCP server, built on
the official SDK so that its protocol layer is conformant and only its payload is
wrong. Violations are toggled individually:

```bash
qs-preflight mock-server --list-violations
qs-preflight mock-server --violations tool-count,schema-draft
```

Adding a violation there is usually the easiest way to prove a new rule fires.

## Reporting a constraint

If Amazon Quick behaves differently from its documentation, that is worth
reporting even without a patch. Open an issue including the endpoint behaviour
observed, the date, and the region if known. Findings confirmed against a live
account are recorded in `docs/findings.md`.
