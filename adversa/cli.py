"""ADVERSA command-line interface.

Usage:
  adversa scan [--target echo|transcript] [--transcript FILE]
               [--probes FILE] [--format table|json]
               [--severity-threshold low|medium|high|critical] [--fail-on-findings]
  adversa list-probes [--probes FILE] [--format table|json]
  adversa --version

Default target is 'transcript' when --transcript is given, else 'echo'.
The 'echo' target simply returns the prompt back (a deliberately *insecure*
model that obeys every injection) so the tool produces real findings out of
the box for demos and CI. Point --transcript at recorded model replies to
red-team a real endpoint offline.

Exit codes:
  0  no findings at/above threshold
  1  findings at/above threshold (when --fail-on-findings, the default)
  2  usage / file error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Report,
    builtin_probes,
    load_probes,
    load_transcript,
    run_probes,
    severity_rank,
    transcript_target,
)


def _echo_target(prompt: str) -> str:
    """An intentionally compliant 'model': echoes the attack back verbatim.

    This represents a worst-case, fully-injectable target. It will trip most
    success detectors, which is what we want for a runnable demo and CI gate.
    """
    return prompt


def _resolve_probes(args) -> list:
    if getattr(args, "probes", None):
        return load_probes(args.probes)
    return builtin_probes()


def _print_table(report: Report, threshold: int) -> None:
    print(f"ADVERSA scan against: {report.target}")
    print(f"  probes run : {report.total}")
    print(f"  resisted   : {report.passed}")
    print(f"  findings   : {report.failed}")
    print(f"  ASR        : {report.attack_success_rate:.0%}  (attack success rate)")
    print(f"  worst sev  : {report.worst_severity}")
    if report.findings:
        print("")
        print("  FINDINGS (model fell for the attack):")
        print("  {:<6} {:<8} {:<13} {:<10} {}".format(
            "ID", "OWASP", "ATLAS", "SEVERITY", "PROBE"))
        for f in sorted(report.findings, key=lambda x: -severity_rank(x.severity)):
            mark = "!!" if severity_rank(f.severity) >= threshold else "  "
            print("  {} {:<4} {:<8} {:<13} {:<10} {}".format(
                mark, f.probe_id, f.category, f.atlas, f.severity, f.name))
    else:
        print("\n  No successful attacks detected.")


def _cmd_scan(args) -> int:
    probes = _resolve_probes(args)

    target_name = args.target
    if args.transcript and args.target == "echo":
        target_name = "transcript"
    if target_name == "transcript":
        if not args.transcript:
            print("error: --target transcript requires --transcript FILE", file=sys.stderr)
            return 2
        pairs = load_transcript(args.transcript)
        # Allow transcripts keyed by probe id: expand to prompt->reply.
        by_id = {p.id: p.prompt for p in probes}
        expanded = {}
        for key, val in pairs.items():
            if key in by_id:
                expanded[by_id[key]] = val
            else:
                expanded[key] = val
        target = transcript_target(expanded)
        label = args.transcript
    else:
        target = _echo_target
        label = "echo (insecure demo model)"

    report = run_probes(probes, target, target_name=label)
    threshold = severity_rank(args.severity_threshold)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_table(report, threshold)

    gating = [f for f in report.findings if severity_rank(f.severity) >= threshold]
    if gating and args.fail_on_findings:
        return 1
    return 0


def _cmd_list_probes(args) -> int:
    probes = _resolve_probes(args)
    if args.format == "json":
        print(json.dumps(
            [{"id": p.id, "name": p.name, "category": p.category,
              "atlas": p.atlas, "severity": p.severity,
              "description": p.description} for p in probes],
            indent=2))
    else:
        print("{:<6} {:<8} {:<13} {:<10} {}".format(
            "ID", "OWASP", "ATLAS", "SEVERITY", "NAME"))
        for p in probes:
            print("{:<6} {:<8} {:<13} {:<10} {}".format(
                p.id, p.category, p.atlas, p.severity, p.name))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="ADVERSA - LLM red-team harness (OWASP LLM Top 10 + MITRE ATLAS).",
        epilog="Example: adversa scan --transcript demos/01-basic/transcript.json --format table",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    def add_common(sp):
        sp.add_argument("--probes", metavar="FILE",
                        help="JSON file of custom probes (defaults to built-in pack)")
        sp.add_argument("--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")

    sp_scan = sub.add_parser("scan", help="run attack probes against a target")
    add_common(sp_scan)
    sp_scan.add_argument("--target", choices=["echo", "transcript"], default="echo",
                         help="target model adapter (default: echo)")
    sp_scan.add_argument("--transcript", metavar="FILE",
                         help="recorded model replies (JSON) to red-team offline")
    sp_scan.add_argument("--severity-threshold",
                         choices=["low", "medium", "high", "critical"], default="low",
                         help="minimum severity that gates the exit code (default: low)")
    sp_scan.add_argument("--no-fail-on-findings", dest="fail_on_findings",
                         action="store_false",
                         help="always exit 0 even when attacks succeed")
    sp_scan.set_defaults(func=_cmd_scan, fail_on_findings=True)

    sp_list = sub.add_parser("list-probes", help="show the loaded attack pack")
    add_common(sp_list)
    sp_list.set_defaults(func=_cmd_list_probes)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
