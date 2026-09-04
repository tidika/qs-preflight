"""Rule tests: each rule is asserted in both its passing and failing state.

A rule exercised only by a failing test may fire indiscriminately. A rule
exercised only by a passing test may never fire at all. Both defects are severe
in a compatibility checker, and the second is more dangerous because it presents
as a clean result.
"""

from __future__ import annotations

from qs_preflight.findings import Severity, Status
from qs_preflight.rules.dcr import DcrAvailableRule
from qs_preflight.rules.headers import HeaderIndependenceRule
from qs_preflight.rules.latency import LatencyRule, LatencyWarnRule
from qs_preflight.rules.oauth_discovery import OAuthDiscoveryPathRule
from qs_preflight.rules.oauth_reachability import OAuthReachabilityRule
from qs_preflight.rules.oauth_scopes import OAuthScopesRule
from qs_preflight.rules.schema_draft import SchemaDraftRule
from qs_preflight.rules.tool_annotations import ToolAnnotationsRule
from qs_preflight.rules.tool_count import ToolCountRule
from qs_preflight.rules.tool_list_stability import ToolListStabilityRule
from qs_preflight.rules.transport import TransportRule

from conftest import make_tools


# --------------------------------------------------------------------------- #
# tool-count -- the boundary here was measured against live Quick, so the
# off-by-one cases matter more than usual: 100 registers, 101 destroys the
# connector.
# --------------------------------------------------------------------------- #

def test_tool_count_green(evidence):
    f = ToolCountRule().check(evidence(tool_count=42))
    assert f.status is Status.PASS
    assert "42 tools" in f.headline


def test_tool_count_green_exactly_at_the_cap(evidence):
    assert ToolCountRule().check(evidence(tool_count=100)).status is Status.PASS


def test_tool_count_red_one_over_the_cap(evidence):
    f = ToolCountRule().check(evidence(tool_count=101))
    assert f.status is Status.FAIL
    assert f.is_blocking


def test_tool_count_red_names_the_excess(evidence):
    f = ToolCountRule().check(evidence(tool_count=142))
    body = " ".join(f.detail)
    assert "42 tools are past the cap" in body
    assert "FAILS OUTRIGHT" in body, "must report observed behaviour, not the documented claim"
    assert f.verified is True
    assert f.remediation


# --------------------------------------------------------------------------- #
# schema-draft -- the false-positive risk is the point. Draft 7 "or later" means
# a modern 2020-12 schema must pass.
# --------------------------------------------------------------------------- #

def test_schema_draft_green_modern_schema(evidence):
    f = SchemaDraftRule().check(evidence(tool_count=10, draft3=False))
    assert f.status is Status.PASS


def test_schema_draft_green_explicit_2020_12(evidence):
    ev = evidence(tool_count=3)
    for tool in ev.tools:
        tool.input_schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert SchemaDraftRule().check(ev).status is Status.PASS


def test_schema_draft_red_boolean_required(evidence):
    f = SchemaDraftRule().check(evidence(tool_count=10, draft3=True))
    assert f.status is Status.FAIL
    assert f.is_blocking
    assert 'required": true' in " ".join(f.detail) or "Draft 3 form" in " ".join(f.detail)


def test_schema_draft_red_declared_legacy_dialect(evidence):
    ev = evidence(tool_count=2)
    ev.tools[0].input_schema["$schema"] = "http://json-schema.org/draft-03/schema#"
    assert SchemaDraftRule().check(ev).status is Status.FAIL


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def test_transport_green(evidence):
    assert TransportRule().check(evidence()).status is Status.PASS


def test_transport_red_stdio(evidence):
    f = TransportRule().check(evidence(transport="stdio"))
    assert f.status is Status.FAIL and f.is_blocking
    assert "stdio" in f.headline


def test_transport_red_handshake_failed(evidence):
    ev = evidence(transport="unreachable", initialize_error="connection refused")
    assert TransportRule().check(ev).status is Status.FAIL


def test_transport_red_sse_only(evidence):
    assert TransportRule().check(evidence(transport="sse")).status is Status.FAIL


# --------------------------------------------------------------------------- #
# latency and reliability
# --------------------------------------------------------------------------- #

def test_latency_green(evidence):
    f = LatencyRule().check(evidence(latencies=[1.0, 1.2, 0.9]))
    assert f.status is Status.PASS


def test_latency_red_over_hard_limit(evidence):
    f = LatencyRule().check(evidence(latencies=[10.0, 61.0, 62.0]))
    assert f.status is Status.FAIL and f.is_blocking
    assert "424" in " ".join(f.detail)


def test_latency_red_in_the_warning_band(evidence):
    f = LatencyRule().check(evidence(latencies=[46.0, 48.0, 50.0]))
    assert f.status is Status.FAIL
    assert "very little margin" in " ".join(f.detail)


def test_retry_exposure_green(evidence):
    assert LatencyWarnRule().check(evidence(failures=0)).status is Status.PASS


def test_retry_exposure_red_any_flake_at_all(evidence):
    f = LatencyWarnRule().check(evidence(failures=1))
    assert f.status is Status.FAIL
    assert f.severity is Severity.WARN


# --------------------------------------------------------------------------- #
# tool list stability
# --------------------------------------------------------------------------- #

def test_tool_list_stability_green(evidence):
    assert ToolListStabilityRule().check(evidence()).status is Status.PASS


def test_tool_list_stability_red_membership_changed(evidence):
    ev = evidence(tool_count=10)
    ev.tools_second_fetch = [t.name for t in ev.tools][:-1] + ["something_new"]
    f = ToolListStabilityRule().check(ev)
    assert f.status is Status.FAIL
    assert "appeared" in " ".join(f.detail)


def test_tool_list_stability_red_order_changed(evidence):
    ev = evidence(tool_count=10)
    ev.tools_second_fetch = list(reversed([t.name for t in ev.tools]))
    f = ToolListStabilityRule().check(ev)
    assert f.status is Status.FAIL
    assert "different order" in f.headline


# --------------------------------------------------------------------------- #
# OAuth
# --------------------------------------------------------------------------- #

def test_oauth_scopes_green(evidence):
    f = OAuthScopesRule().check(evidence(scopes=["mcp:tools"]))
    assert f.status is Status.PASS


def test_oauth_scopes_red_when_absent(evidence):
    f = OAuthScopesRule().check(evidence(scopes=None))
    assert f.status is Status.FAIL and f.is_blocking


def test_dcr_green(evidence):
    ev = evidence(registration_endpoint="https://auth.example.com/register")
    assert DcrAvailableRule().check(ev).status is Status.PASS


def test_dcr_red_is_only_a_warning(evidence):
    f = DcrAvailableRule().check(evidence(registration_endpoint=None))
    assert f.status is Status.FAIL
    assert f.severity is Severity.WARN, "manual credentials are a documented fallback"
    assert not f.is_blocking


def test_oauth_discovery_green_at_root(evidence):
    f = OAuthDiscoveryPathRule().check(evidence(prm_at_root=True))
    assert f.status is Status.PASS


def test_oauth_discovery_red_path_only(evidence):
    f = OAuthDiscoveryPathRule().check(evidence(prm_at_root=False, prm_at_path=True))
    assert f.status is Status.FAIL


def test_oauth_reachability_green(evidence):
    assert OAuthReachabilityRule().check(evidence()).status is Status.PASS


def test_oauth_reachability_red_private_idp(evidence):
    f = OAuthReachabilityRule().check(evidence(private_oauth_host=True))
    assert f.status is Status.FAIL and f.is_blocking
    assert "10.0.0.5" in " ".join(f.detail)


# --------------------------------------------------------------------------- #
# headers and annotations
# --------------------------------------------------------------------------- #

def test_header_independence_green(evidence):
    assert HeaderIndependenceRule().check(evidence()).status is Status.PASS


def test_header_independence_red_x_mcp_header(evidence):
    ev = evidence(tool_count=3)
    ev.tools[0].input_schema["properties"]["region"] = {
        "type": "string",
        "x-mcp-header": "Region",
    }
    f = HeaderIndependenceRule().check(ev)
    assert f.status is Status.FAIL
    assert "Mcp-Param-Region" in " ".join(f.detail)


def test_tool_annotations_green_when_declared(evidence):
    f = ToolAnnotationsRule().check(evidence(tool_count=10, annotate=True))
    assert f.status is Status.PASS


def test_tool_annotations_red_predicts_misclassification(evidence):
    # *_audit and *_export describe themselves as reading, but end in verbs
    # Quick was observed classifying as writes.
    f = ToolAnnotationsRule().check(evidence(tool_count=10, annotate=False))
    assert f.status is Status.FAIL
    body = " ".join(f.detail)
    assert "inventory_audit" in body
    assert "inventory_export" in body


def test_tool_annotations_green_when_nothing_looks_misread():
    from qs_preflight.evidence import Evidence

    ev = Evidence(target="x", tools=make_tools(2))  # lookup + search only
    assert ToolAnnotationsRule().check(ev).status is Status.PASS
