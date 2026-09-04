"""Command line entry point for the mock server.

    python -m qs_preflight._mock --violations tool-count
    python -m qs_preflight._mock --violations tool-count,pagination
    python -m qs_preflight._mock --violations schema-draft
    python -m qs_preflight._mock --profile clean

The flags configure how this *server* is broken. They have nothing to do with
which rules `qs-preflight check` runs -- that command always runs every rule.
"""

from __future__ import annotations

import argparse
import sys

import uvicorn

from . import auth, catalogue, violations as vio
from .server import MCP_PATH, build_app


def _print_violations() -> None:
    print("Available violations:\n")
    width = max(len(v) for v in vio.VIOLATIONS)
    for name, v in sorted(vio.VIOLATIONS.items()):
        print(f"  {name:<{width}}  [{v.cause}]")
        print(f"  {'':<{width}}  {v.summary}")
        print(f"  {'':<{width}}  feeds rule: {v.feeds_rule}\n")
    print("Profiles:\n")
    for name, members in sorted(vio.PROFILES.items()):
        print(f"  {name:<12} {', '.join(sorted(members)) or '(nothing broken)'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qs-preflight mock-server",
        description="A deliberately non-compliant MCP server, for testing qs-preflight.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8931)
    parser.add_argument("--profile", help="named violation set: clean, noncompliant")
    parser.add_argument("--violations", help="comma-separated violation ids")
    parser.add_argument(
        "--list-violations", action="store_true", help="describe every violation and exit"
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        help="reply with plain JSON instead of an SSE stream",
    )
    parser.add_argument(
        "--tool-count",
        type=int,
        help="serve exactly N tools, overriding the profile. Used to bisect where "
             "Quick's 100-tool cap actually starts failing.",
    )
    parser.add_argument(
        "--wire-log",
        action="store_true",
        help="log JSON-RPC method, protocol version, and 4xx bodies for every request",
    )
    parser.add_argument(
        "--public-url",
        help=(
            "externally visible base URL, e.g. https://x.trycloudflare.com. "
            "Enables the OAuth endpoints and prints the credentials to paste "
            "into the Quick console. Required because Quick's console offers no "
            "'no authentication' option, despite AWS documenting one."
        ),
    )
    args = parser.parse_args(argv)

    if args.list_violations:
        _print_violations()
        return 0

    try:
        active = vio.resolve(args.profile, args.violations)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if args.tool_count:
        catalogue.override_count(args.tool_count)
        active.add("tool-count")
    count = catalogue.FULL_COUNT if "tool-count" in active else catalogue.CLEAN_COUNT
    dropped = max(0, count - 100)

    print(f"  mock MCP server  ·  http://{args.host}:{args.port}{MCP_PATH}")
    print(f"  tools exposed    ·  {count}")
    if active:
        for name in sorted(active):
            v = vio.VIOLATIONS[name]
            print(f"  violation        ·  {name}  [{v.cause}]")
    else:
        print("  violations       ·  none (compliant baseline)")
    if "pagination" in active:
        print(f"  paged            ·  {vio.PAGE_SIZE} tools per page, nextCursor set")
    if dropped:
        names = [t.name for t in catalogue.tools(count)][100:]
        print(f"  Quick would drop ·  {dropped} tools, starting at {names[0]}")

    public = (args.public_url or "").rstrip("/")
    if public:
        print(f"  public base      ·  {public}")
        print()
        print("  Paste into the Quick console (Service authentication):")
        for label, value in auth.console_values(public):
            print(f"      {label:<14}  {value}")
        print(f"      {'MCP endpoint':<14}  {public}{MCP_PATH}")
    print()

    uvicorn.run(
        build_app(
            active,
            json_response=args.json_response,
            public_url=public or None,
            wire_log=args.wire_log,
        ),
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
