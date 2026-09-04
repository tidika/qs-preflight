"""Rule contract and registry.

Each rule is a self-contained class registered through the ``register``
decorator. Adding a rule requires one module in this package and one import line
in ``rules/__init__.py``.

Every rule carries a citation to the documentation that justifies it. A finding
without a citation cannot be independently verified, so ``doc_verified`` remains
False until the referenced document has been reviewed and confirmed to state the
constraint the rule enforces. The test suite fails while any registered rule is
unverified.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .. import docs
from ..evidence import Evidence
from ..findings import Finding, Severity, Status

REGISTRY: list[type["Rule"]] = []


def register(cls: type["Rule"]) -> type["Rule"]:
    if any(r.id == cls.id for r in REGISTRY):
        raise ValueError(f"duplicate rule id: {cls.id}")
    REGISTRY.append(cls)
    return cls


class Rule(ABC):
    id: str
    title: str
    severity: Severity
    doc_verified: bool = False

    # Evidence fields this rule needs. Anything missing means SKIP with a
    # reason, never FAIL. Reporting five OAuth blockers against a server with
    # no authentication is the fastest way to get a checker uninstalled.
    requires: tuple[str, ...] = ()

    @property
    def doc_url(self) -> str:
        return docs.url_for(self.id)

    @property
    def measured(self) -> str:
        """Behaviour observed against a live Amazon Quick account, where it
        differs from the published documentation. Empty when the rule rests on
        documentation alone."""
        return docs.measured(self.id)

    @abstractmethod
    def check(self, ev: Evidence) -> Finding:
        """A pure function of the evidence bundle. No network, no printing."""

    # -- helpers, so concrete rules stay short --------------------------------

    def _finding(
        self,
        status: Status,
        headline: str,
        detail: list[str] | None = None,
        remediation: str = "",
        doc_url: str | None = None,
    ) -> Finding:
        # `doc_url` overrides the rule's default citation. Some rules cover more
        # than one condition, and those conditions are not always justified by
        # the same document; citing the wrong source would defeat the purpose of
        # attaching a citation at all.
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            headline=headline,
            doc_url=doc_url or self.doc_url,
            detail=detail or [],
            remediation=remediation,
            verified=bool(self.measured),
        )

    def passed(self, headline: str, detail: list[str] | None = None) -> Finding:
        return self._finding(Status.PASS, headline, detail)

    def failed(
        self,
        headline: str,
        detail: list[str] | None = None,
        remediation: str = "",
        doc_url: str | None = None,
    ) -> Finding:
        return self._finding(Status.FAIL, headline, detail, remediation, doc_url)

    def skipped(self, reason: str) -> Finding:
        return self._finding(Status.SKIP, reason)

    def errored(self, reason: str) -> Finding:
        return self._finding(Status.ERROR, reason)
