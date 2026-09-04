"""Output formats.

Three renderings of the same `Report`, none of which contains any judgement of
its own. That is what makes them cheap: a rule is written once and appears in all
three, and `--json` can never disagree with the terminal because neither decides
anything.
"""

from __future__ import annotations

import json as _json

from ..findings import Report
from . import markdown as _markdown
from . import terminal as _terminal

render_terminal = _terminal.render
render_markdown = _markdown.render


def render_json(report: Report, indent: int = 2) -> str:
    return _json.dumps(report.to_dict(), indent=indent)


__all__ = ["render_terminal", "render_markdown", "render_json"]
