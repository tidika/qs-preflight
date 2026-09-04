"""Declaration of read and write intent through MCP tool annotations.

This rule derives from observed behaviour rather than published documentation.

The Amazon Quick connector wizard contains two undocumented steps, Manage Write
Permissions and Manage Read Permissions, which classify every tool as Read or
Write. Tools classified as Write default to requiring user approval on each
invocation.

Where a server declares no MCP ``annotations``, Amazon Quick has no authoritative
signal and infers intent from the tool name. Observed on 2026-08-27 across 100
tools spanning multiple entities, the classification was consistent::

    classified WRITE:  adjust  audit  create  delete  export  reconcile  update
    classified READ:   list    lookup  search

Two of those verbs identify read-only operations. Tools named ``*_audit``
("Return the change history for a record") and ``*_export`` ("Export records in a
downloadable format") were both classified as writes. Confirmed in conversation:
a lookup executed without prompting, while an audit request produced an approval
request.

Whether declaring ``annotations.readOnlyHint`` overrides the inference has not
been established, so this rule reports the risk and the likely remedy without
asserting that the remedy is effective.
"""

from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .base import Rule, register

# Verbs observed being classified as Write by Quick, 2026-08-27.
_INFERRED_WRITE = ("adjust", "audit", "create", "delete", "export", "reconcile", "update")

# Words in a description suggesting the tool only reads, despite its name.
_READ_ONLY_LANGUAGE = ("return", "fetch", "retrieve", "list", "read", "export", "report", "view")

_PREVIEW = 6


@register
class ToolAnnotationsRule(Rule):
    id = "tool-annotations"
    title = "Tools declare read/write intent rather than leaving Quick to guess"
    severity = Severity.WARN
    doc_verified = True
    requires = ("tools",)

    def check(self, ev: Evidence) -> Finding:
        annotated = [t for t in ev.tools if t.annotations]
        unannotated = [t for t in ev.tools if not t.annotations]

        # Tools Quick's name-based classifier will call writes, whose own
        # descriptions read as read-only. These are the ones that will nag users.
        likely_misread = []
        for tool in unannotated:
            verb = tool.name.rsplit("_", 1)[-1].lower()
            if verb not in _INFERRED_WRITE:
                continue
            description = tool.description.lower()
            if any(word in description for word in _READ_ONLY_LANGUAGE):
                likely_misread.append(tool.name)

        if not unannotated:
            return self.passed(
                f"all {len(ev.tools)} tools declare annotations",
                [
                    "note: whether Quick honours annotations rather than inferring from "
                    "the tool name is untested."
                ],
            )

        if not likely_misread:
            return self.passed(
                f"{len(unannotated)} tools lack annotations, none likely misclassified",
                [
                    "Quick infers read/write from the tool name. No unannotated tool here "
                    "combines a write-sounding name with a read-only description.",
                    f"{len(annotated)} of {len(ev.tools)} tools declare annotations.",
                ],
            )

        return self.failed(
            f"{len(likely_misread)} read-only tools will likely be classified as writes",
            detail=[
                ", ".join(likely_misread[:_PREVIEW]),
                *(
                    [f"... and {len(likely_misread) - _PREVIEW} more"]
                    if len(likely_misread) > _PREVIEW
                    else []
                ),
                "",
                "These tools describe themselves as reading data, but their names end in a",
                "verb Quick was observed classifying as a write. Writes default to",
                "'Always ask', so every call interrupts the user for approval.",
                "",
                "Undocumented behaviour, observed against a live Amazon Quick",
                "account on 2026-08-27.",
            ],
            remediation=(
                "Declare annotations.readOnlyHint on read-only tools, and consider naming "
                "them with unambiguous verbs. Whether Quick honours annotations is not yet "
                "confirmed — but leaving it to guess is known to go wrong."
            ),
        )
