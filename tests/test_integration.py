"""End-to-end, against the mock server over real HTTP.

Unit tests over constructed evidence cannot establish that the probe works.
These tests start the mock server in-process, run the real probe against it, and
evaluate the real rules, which is the only way to detect defects arising at the
boundaries between components.

The mock is broken selectively by flag, so the same fixture proves a rule red and
green one argument apart.
"""

from __future__ import annotations

import socket
import threading
import time
from contextlib import closing

import pytest
import uvicorn

import qs_preflight.rules  # noqa: F401
from qs_preflight._mock.server import build_app
from qs_preflight.engine import run_rules
from qs_preflight.findings import Status
from qs_preflight.probe import probe


def _free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    def __init__(self, violations: set[str]):
        self.port = _free_port()
        config = uvicorn.Config(
            build_app(violations), host="127.0.0.1", port=self.port, log_level="error"
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def __enter__(self):
        self.thread.start()
        deadline = time.time() + 15
        while time.time() < deadline:
            if getattr(self.server, "started", False):
                return self
            time.sleep(0.05)
        raise RuntimeError("mock server did not start")

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)


def _run(violations: set[str], **probe_kwargs):
    with _Server(violations) as server:
        ev = probe(server.url, samples=2, timeout=15, **probe_kwargs)
        return ev, run_rules(ev)


@pytest.mark.slow
def test_compliant_server_passes_end_to_end():
    ev, report = _run(set())

    assert ev.transport == "streamable-http"
    assert len(ev.tools) == 12
    assert report.exit_code() == 0
    assert not report.blockers

    by_id = {f.rule_id: f for f in report.findings}
    assert by_id["tool-count"].status is Status.PASS
    assert by_id["schema-draft"].status is Status.PASS
    assert by_id["transport"].status is Status.PASS


@pytest.mark.slow
def test_too_many_tools_is_caught_end_to_end():
    ev, report = _run({"tool-count"})

    assert len(ev.tools) == 142
    by_id = {f.rule_id: f for f in report.findings}
    assert by_id["tool-count"].status is Status.FAIL
    assert by_id["tool-count"].is_blocking
    assert report.exit_code() == 1


@pytest.mark.slow
def test_draft3_schemas_are_caught_end_to_end():
    ev, report = _run({"schema-draft"})

    by_id = {f.rule_id: f for f in report.findings}
    assert by_id["schema-draft"].status is Status.FAIL
    assert by_id["schema-draft"].is_blocking


@pytest.mark.slow
def test_probe_follows_pagination_and_assembles_every_page():
    """MCP permits paginating tools/list. A checker that stops at page one would
    under-count tools and wrongly pass a server over the cap."""
    ev, report = _run({"tool-count", "pagination"})

    assert ev.paginated is True
    assert ev.pages_fetched == 3
    assert len(ev.tools) == 142

    by_id = {f.rule_id: f for f in report.findings}
    assert by_id["tool-count"].status is Status.FAIL


@pytest.mark.slow
def test_unauthenticated_server_skips_oauth_rules_rather_than_failing_them():
    _, report = _run(set())
    oauth_rules = [
        f for f in report.findings if f.rule_id.startswith(("oauth-", "dcr-"))
    ]
    assert oauth_rules
    assert all(f.status is Status.SKIP for f in oauth_rules)
    assert all(f.headline for f in oauth_rules), "a skip must always carry a reason"


def test_stdio_target_is_rejected_without_touching_the_network():
    ev = probe("npx @modelcontextprotocol/server-filesystem")
    assert ev.transport == "stdio"
    assert "remote servers only" in ev.probe_errors["target"]

    report = run_rules(ev)
    by_id = {f.rule_id: f for f in report.findings}
    assert by_id["transport"].status is Status.FAIL
    assert by_id["transport"].is_blocking
