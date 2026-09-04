"""JSON Schema dialect of each tool's ``inputSchema``.

This is not a check for Draft 7 specifically. AWS accepts "Draft 7 or later",
and the MCP specification defaults schemas without a ``$schema`` field to
2020-12. A rule requiring Draft 7 exactly would reject conformant modern servers,
which is a false positive.

The condition that actually causes failure is the deprecated Draft 3 form, in
which ``required`` is a boolean inside a property rather than an array at the
schema root. From Draft 4 onwards ``required`` remains a valid keyword but must
hold an array. Amazon Quick validates against the meta-schema, encounters a
boolean where an array is required, and rejects the tool definition.

The schema remains valid JSON throughout and parses without error; only its
meaning is wrong. This is why the resulting failure is difficult to diagnose,
and why AWS notes that connector creation "hangs for two to five minutes before
it fails".
"""

from __future__ import annotations

from typing import Any

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register

_PREVIEW = 6

# Dialects predating Draft 4, where `required` was a per-property boolean.
_LEGACY_DIALECTS = ("draft-03", "draft-02", "draft-01", "hyper-schema/draft-03")


def _legacy_required(schema: dict[str, Any]) -> list[str]:
    """Property names using the Draft 3 boolean form."""
    offenders = []
    for name, prop in (schema.get("properties") or {}).items():
        if isinstance(prop, dict) and isinstance(prop.get("required"), bool):
            offenders.append(name)
    return offenders


def _declared_legacy_dialect(schema: dict[str, Any]) -> str | None:
    declared = schema.get("$schema")
    if not isinstance(declared, str):
        return None
    return declared if any(d in declared for d in _LEGACY_DIALECTS) else None


@register
class SchemaDraftRule(Rule):
    id = "schema-draft"
    title = "Tool inputSchema is JSON Schema Draft 7 or later"
    severity = Severity.BLOCKER
    doc_verified = True
    requires = ("tools",)

    def check(self, ev: Evidence) -> Finding:
        boolean_required: list[str] = []
        legacy_dialect: list[str] = []
        missing_schema: list[str] = []

        for tool in ev.tools:
            schema = tool.input_schema
            if not isinstance(schema, dict) or not schema:
                missing_schema.append(tool.name)
                continue
            if _legacy_required(schema):
                fields = ", ".join(_legacy_required(schema))
                boolean_required.append(f"{tool.name} ({fields})")
            if _declared_legacy_dialect(schema):
                legacy_dialect.append(f"{tool.name} ({schema['$schema']})")

        problems = boolean_required + legacy_dialect + missing_schema
        if not problems:
            return self.passed(
                f"all {len(ev.tools)} inputSchema definitions are Draft 7 or later",
                ["no Draft 3 `\"required\": true` found inside any property"],
            )

        detail: list[str] = []
        if boolean_required:
            detail += [
                f'{len(boolean_required)} tools use the Draft 3 form, '
                '`"required": true` inside a property:',
                ", ".join(boolean_required[:_PREVIEW]),
            ]
            if len(boolean_required) > _PREVIEW:
                detail.append(f"... and {len(boolean_required) - _PREVIEW} more")
        if legacy_dialect:
            detail += ["", f"{len(legacy_dialect)} tools declare a pre-Draft-7 $schema:",
                       ", ".join(legacy_dialect[:_PREVIEW])]
        if missing_schema:
            detail += ["", f"{len(missing_schema)} tools have no usable inputSchema object:",
                       ", ".join(missing_schema[:_PREVIEW])]

        detail += [
            "",
            "This will surface as `Creation failed`, typically after the console hangs",
            "for two to five minutes -- AWS notes that delay is internal publish retries,",
            "not a network timeout.",
        ]

        return self.failed(
            f"{len(problems)} of {len(ev.tools)} tools have an unusable inputSchema",
            detail=detail,
            remediation=(
                "Move `required` to an array of property names at the schema root, as a "
                "sibling of `properties`. Many MCP frameworks and code generators still "
                "emit Draft 3 by default -- check your framework for the option that "
                "selects the JSON Schema output version."
            ),
        )
