"""The tool inventory the mock server exposes.

A warehouse and procurement domain, not `tool_001`. This matters more than it
looks: the whole point of the tool-count rule is naming the capabilities that
silently disappear, and "tool_100, tool_101" reads as a toy while
"return_order_create, invoice_reconcile" reads as somebody's actual system
quietly losing the ability to process returns.

Ordering is deliberate. Tools are grouped by entity, the way a real server
groups them -- which means Quick's cut at 100 does not remove a random
scattering. It removes *every* capability for the last few entities. Returns,
invoicing, forecasting and cycle counts vanish completely while inventory and
purchasing survive intact.
"""

from __future__ import annotations

from typing import Any

# Order is load-bearing: entities 1-10 produce the 100 tools that survive
# Quick's cap, entities 11-15 produce the casualties.
ENTITIES: list[tuple[str, str]] = [
    ("inventory", "inventory records"),
    ("sku", "SKU definitions"),
    ("warehouse", "warehouse locations"),
    ("batch", "batch and lot records"),
    ("purchase_order", "purchase orders"),
    ("supplier", "supplier accounts"),
    ("shipment", "outbound shipments"),
    ("carrier", "carrier accounts and rates"),
    ("pick_list", "pick lists"),
    ("putaway", "putaway tasks"),
    # --- everything below here is dropped when the server exposes 142 tools ---
    ("return_order", "customer returns"),
    ("invoice", "supplier invoices"),
    ("forecast", "demand forecasts"),
    ("cycle_count", "cycle count sessions"),
    ("receiving", "inbound receipts"),
]

# (operation, description template, properties, required)
OPERATIONS: list[tuple[str, str, dict[str, Any], list[str]]] = [
    (
        "lookup", "Fetch a single record from {desc} by identifier.",
        {"id": {"type": "string", "description": "Record identifier"}},
        ["id"],
    ),
    (
        "search", "Search {desc} by free-text query.",
        {
            "query": {"type": "string", "description": "Search expression"},
            "limit": {"type": "integer", "description": "Maximum results", "minimum": 1},
        },
        ["query"],
    ),
    (
        "create", "Create a new record in {desc}.",
        {
            "payload": {"type": "object", "description": "Record body"},
            "dry_run": {"type": "boolean", "description": "Validate without persisting"},
        },
        ["payload"],
    ),
    (
        "update", "Apply a partial update to a record in {desc}.",
        {
            "id": {"type": "string", "description": "Record identifier"},
            "patch": {"type": "object", "description": "Fields to change"},
        },
        ["id", "patch"],
    ),
    (
        "delete", "Remove a record from {desc}.",
        {"id": {"type": "string", "description": "Record identifier"}},
        ["id"],
    ),
    (
        "list", "Page through {desc}.",
        {
            "cursor": {"type": "string", "description": "Opaque pagination cursor"},
            "limit": {"type": "integer", "description": "Page size", "minimum": 1},
        },
        [],
    ),
    (
        "audit", "Return the change history for a record in {desc}.",
        {
            "id": {"type": "string", "description": "Record identifier"},
            "since": {"type": "string", "description": "ISO-8601 lower bound"},
        },
        ["id"],
    ),
    (
        "adjust", "Apply a signed quantity or value adjustment within {desc}.",
        {
            "id": {"type": "string", "description": "Record identifier"},
            "delta": {"type": "integer", "description": "Signed adjustment"},
            "reason": {"type": "string", "description": "Adjustment reason code"},
        },
        ["id", "delta"],
    ),
    (
        "export", "Export {desc} in a downloadable format.",
        {"format": {"type": "string", "enum": ["csv", "json", "parquet"]}},
        ["format"],
    ),
    (
        "reconcile", "Reconcile {desc} against an external system of record.",
        {
            "id": {"type": "string", "description": "Record identifier"},
            "target": {"type": "string", "description": "External system key"},
        },
        ["id", "target"],
    ),
]

FULL_COUNT = 142       # deliberately above Amazon Quick's documented cap of 100
CLEAN_COUNT = 12       # a small, comfortably compliant server


class MockTool:
    __slots__ = ("name", "description", "input_schema")

    def __init__(self, name: str, description: str, input_schema: dict[str, Any]) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema


def _build_all() -> list[MockTool]:
    tools: list[MockTool] = []
    for entity, desc in ENTITIES:
        for op, template, properties, required in OPERATIONS:
            schema: dict[str, Any] = {
                "type": "object",
                "properties": {k: dict(v) for k, v in properties.items()},
            }
            if required:
                schema["required"] = list(required)
            tools.append(
                MockTool(
                    name=f"{entity}_{op}",
                    description=template.format(desc=desc),
                    input_schema=schema,
                )
            )
    return tools


_ALL = _build_all()


def override_count(n: int) -> None:
    """Set how many tools `tool-count` mode serves.

    Exists for bisecting Quick's cap. A 142-tool server failed connector
    creation outright while a 12-tool server succeeded; "fails above 100" and
    "fails somewhere above 100" are different claims, and only a bisect
    distinguishes them.
    """
    global FULL_COUNT
    if not 1 <= n <= len(_ALL):
        raise ValueError(f"tool count must be between 1 and {len(_ALL)}")
    FULL_COUNT = n


def tools(count: int) -> list[MockTool]:
    """The first `count` tools, in the catalogue's deliberate order."""
    if count > len(_ALL):
        raise ValueError(f"catalogue holds {len(_ALL)} tools, asked for {count}")
    return _ALL[:count]


def to_draft3(schema: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a valid schema into the deprecated Draft 3 form.

    Draft 3 marked a field mandatory with a boolean *inside* the property.
    Draft 4 onwards moved it to an array at the schema root. Quick validates
    against Draft 7 or later, finds `required` holding a boolean where an array
    is mandated, and rejects the tool -- which is AWS's documented most-common
    cause of a connector failing at publish.

    Note what this function does not do: it does not produce malformed JSON.
    The output parses perfectly. It simply means the wrong thing.
    """
    out = dict(schema)
    required = out.pop("required", [])
    if required:
        props = {k: dict(v) for k, v in out.get("properties", {}).items()}
        for field in required:
            if field in props:
                props[field]["required"] = True
        out["properties"] = props
    return out
