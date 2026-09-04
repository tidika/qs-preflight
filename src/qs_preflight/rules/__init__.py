"""Importing this package is what populates the rule registry.

One line per rule. That is the entire cost of adding rule fifteen.
"""

from . import (  # noqa: F401
    dcr,
    headers,
    latency,
    manual_checklist,
    oauth_discovery,
    oauth_reachability,
    oauth_scopes,
    schema_draft,
    tool_annotations,
    tool_count,
    tool_list_stability,
    transport,
)
