"""The switches that make the mock server wrong.

One fixture that can be broken selectively, rather than five mock servers.
That is what lets every rule be proved red *and* green against the same target:
`tool-count` fires at 142 tools and stays quiet at 12, one flag apart.

Note which column each violation sits in. Most of these describe a server that
is doing nothing wrong -- 142 tools is valid MCP, and the specification imposes
no tool limit at all. Only `schema-draft` is a genuine defect. That asymmetry is
the finding, and it is why this mock is built on the official SDK rather than
hand-rolled: the point is not that a broken server fails, it is that a correct
one does.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    id: str
    summary: str
    cause: str          # "Quick restriction" | "Server defect"
    feeds_rule: str


VIOLATIONS: dict[str, Violation] = {
    "tool-count": Violation(
        "tool-count",
        "Expose 142 tools instead of 12. Quick registers the first 100 and drops the rest.",
        "Quick restriction",
        "tool-count",
    ),
    "pagination": Violation(
        "pagination",
        "Serve tools/list in pages of 50 with nextCursor, as MCP permits.",
        "Quick restriction",
        "tool-count",
    ),
    "schema-draft": Violation(
        "schema-draft",
        'Emit deprecated Draft 3 schemas with "required": true inside each property.',
        "Server defect",
        "schema-draft",
    ),
}

PROFILES: dict[str, set[str]] = {
    "clean": set(),
    "noncompliant": {"tool-count", "schema-draft"},
}

PAGE_SIZE = 50


def resolve(profile: str | None, violations: str | None) -> set[str]:
    """Turn --profile / --violations into the active violation set."""
    active: set[str] = set()

    if profile:
        if profile not in PROFILES:
            raise ValueError(
                f"unknown profile {profile!r}; choose from {', '.join(sorted(PROFILES))}"
            )
        active |= PROFILES[profile]

    if violations:
        for name in (v.strip() for v in violations.split(",")):
            if not name:
                continue
            if name not in VIOLATIONS:
                raise ValueError(
                    f"unknown violation {name!r}; choose from {', '.join(sorted(VIOLATIONS))}"
                )
            active.add(name)

    return active
