"""The command line.

    qs-preflight check https://mcp.example.com/mcp
    qs-preflight check <url> --json
    qs-preflight check <url> --markdown       # paste into a PR or ticket
    qs-preflight check <url> --fail-on warn   # stricter CI
    qs-preflight rules --markdown             # regenerate the README table
    qs-preflight mock-server --violations tool-count

Exit codes form the continuous-integration contract, and are the reason this is a
command-line tool rather than a hosted interface: a dashboard cannot fail a pull
request.

    0  no blockers
    1  blockers present (or warnings, with --fail-on warn)
    2  the checker itself could not complete

argparse is used in preference to a third-party command-line framework. This
package is installed into environments it does not control, where each additional
dependency is a potential version conflict.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import report as reporters
from . import rules  # noqa: F401  -- importing populates the rule registry
from .engine import run_rules
from .findings import Severity
from .probe import DEFAULT_PROTOCOL_VERSION, probe
from .rules.base import REGISTRY

VERSION = "0.1.2"

# Preferred over --bearer-token: a flag lands in shell history, in `ps` output,
# and in CI logs that echo their commands. The environment variable does not.
TOKEN_ENV = "QS_PREFLIGHT_TOKEN"


def _cmd_check(args: argparse.Namespace) -> int:
    ev = probe(
        args.url,
        timeout=args.timeout,
        samples=args.samples,
        call_tool=args.call_tool,
        protocol_version=args.protocol_version,
        bearer_token=args.bearer_token or os.environ.get(TOKEN_ENV),
    )
    report = run_rules(ev)

    if args.json or args.markdown:
        # These formats are destined for a file, a clipboard or a PR comment, not
        # for a console. On Windows the default stdout codepage is cp1252 and
        # raises on the markdown status emoji, so force UTF-8 for machine output.
        # The terminal renderer handles this differently: it degrades its glyphs
        # to ASCII, because there the console genuinely may not support them.
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
        print(reporters.render_json(report) if args.json else reporters.render_markdown(report))
    else:
        reporters.render_terminal(report)

    return report.exit_code(fail_on_warn=(args.fail_on == "warn"))


def _cmd_rules(args: argparse.Namespace) -> int:
    """List the rules. `--markdown` regenerates the README table, so the docs
    cannot drift from the code."""
    rules_sorted = sorted(REGISTRY, key=lambda r: (r.severity.value, r.id))

    if args.markdown:
        print("| Rule | Severity | Checks | Source |")
        print("|---|---|---|---|")
        for rule_cls in rules_sorted:
            rule = rule_cls()
            measured = " **[measured]**" if rule.measured else ""
            print(
                f"| `{rule.id}` | {rule.severity.value} | {rule.title}{measured} "
                f"| [docs]({rule.doc_url}) |"
            )
        return 0

    width = max(len(r.id) for r in rules_sorted)
    for rule_cls in rules_sorted:
        rule = rule_cls()
        flag = " [measured]" if rule.measured else ""
        print(f"  {rule.id:<{width}}  {rule.severity.value:<8} {rule.title}{flag}")
    print(f"\n  {len(rules_sorted)} rules. [measured] = verified against a live Quick account.")
    return 0


def _cmd_mock_server(argv: list[str]) -> int:
    from ._mock.__main__ import main as mock_main

    return mock_main(argv)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qs-preflight",
        description="Check whether an MCP server will work with Amazon Quick.",
    )
    parser.add_argument("--version", action="version", version=f"qs-preflight {VERSION}")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="check an MCP server endpoint")
    check.add_argument("url", help="the MCP server URL, e.g. https://example.com/mcp")
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.add_argument(
        "--markdown", action="store_true", help="markdown for a PR comment or ticket"
    )
    check.add_argument(
        "--fail-on",
        choices=["blocker", "warn"],
        default="blocker",
        help="exit 1 on blockers only (default), or on warnings too",
    )
    check.add_argument(
        "--samples", type=int, default=3, help="timing samples per operation (default 3)"
    )
    check.add_argument(
        "--timeout", type=float, default=65.0, help="per-request timeout in seconds"
    )
    check.add_argument(
        "--call-tool",
        metavar="NAME",
        help=(
            "also time this tool via tools/call. Off by default: invoking an unknown "
            "server's tools can have real side effects."
        ),
    )
    check.add_argument(
        "--bearer-token",
        metavar="TOKEN",
        help=(
            f"send Authorization: Bearer TOKEN. Prefer the {TOKEN_ENV} environment "
            "variable instead — a command-line flag is visible in shell history, "
            "process listings and CI logs."
        ),
    )
    check.add_argument(
        "--protocol-version",
        default=DEFAULT_PROTOCOL_VERSION,
        help=f"MCP revision to claim on initialize (default {DEFAULT_PROTOCOL_VERSION})",
    )

    rules_cmd = sub.add_parser("rules", help="list the rules this version checks")
    rules_cmd.add_argument(
        "--markdown", action="store_true", help="emit the README rules table"
    )

    sub.add_parser(
        "mock-server",
        help="run the deliberately non-compliant test server",
        add_help=False,
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # mock-server takes its own flags; hand the rest straight through rather than
    # duplicating its parser here.
    if argv and argv[0] == "mock-server":
        return _cmd_mock_server(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        return _cmd_check(args)
    if args.command == "rules":
        return _cmd_rules(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
