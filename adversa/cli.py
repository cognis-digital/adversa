"""ADVERSA command-line interface.

Subcommands:
  catalog   List the bundled probe catalog (OWASP LLM Top-10 + MITRE ATLAS).
  scan      Run probes against a target and report findings.
  probe     Show full detail (prompts + grader + remediation) for one probe.
  refs      Show the OWASP LLM Top-10 + ATLAS tactic reference tables.

Targets:
  secure | vulnerable      bundled deterministic reference targets
  module:callable          import a user callable target(prompt)->str

Exit codes: 0 = no findings, 1 = findings present, 2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import core


def _emit(text: str) -> None:
    print(text)


def _cmd_catalog(args) -> int:
    probes = core.list_probes(owasp=args.owasp, atlas=args.atlas,
                              min_severity=args.min_severity)
    if args.format == "json":
        _emit(json.dumps(core.render_catalog_json(probes), indent=2))
    else:
        _emit(core.render_catalog_table(probes))
    return 0


def _cmd_refs(args) -> int:
    if args.format == "json":
        _emit(json.dumps({
            "owasp_llm_top10": core.OWASP_LLM,
            "atlas_tactics": core.ATLAS_TACTICS,
        }, indent=2))
    else:
        out = ["OWASP LLM Top-10 (2025):"]
        for k, v in core.OWASP_LLM.items():
            out.append(f"  {k}  {v}")
        out.append("")
        out.append("MITRE ATLAS tactics:")
        for k, v in core.ATLAS_TACTICS.items():
            out.append(f"  {k:<12} {v}")
        _emit("\n".join(out))
    return 0


def _cmd_probe(args) -> int:
    p = core.CATALOG_BY_ID.get(args.id)
    if p is None:
        print(f"[{core.TOOL_NAME}] unknown probe id: {args.id}", file=sys.stderr)
        return 2
    if args.format == "json":
        _emit(json.dumps(core.render_catalog_json([p])["probes"][0], indent=2))
        return 0
    out = [f"{p.pid} - {p.name}",
           f"  OWASP : {p.owasp} {p.owasp_name}",
           f"  ATLAS : {p.atlas} {p.atlas_name}",
           f"  SEV   : {p.severity}",
           f"  desc  : {p.description}",
           f"  fix   : {p.remediation}",
           "  cases :"]
    for i, c in enumerate(p.cases, 1):
        out.append(f"    [{i}] grader={c.grader}")
        out.append(f"        prompt: {c.prompt}")
    _emit("\n".join(out))
    return 0


def _cmd_scan(args) -> int:
    try:
        name, target = core.resolve_target(args.target)
    except Exception as exc:
        print(f"[{core.TOOL_NAME}] {exc}", file=sys.stderr)
        return 2

    probes = core.list_probes(owasp=args.owasp, atlas=args.atlas,
                              min_severity=args.min_severity)
    if args.probe:
        probes = [p for p in probes if p.pid in set(args.probe)]
    if not probes:
        print(f"[{core.TOOL_NAME}] no probes selected", file=sys.stderr)
        return 2

    report = core.scan(target, probes, target_name=name)

    if args.format == "json":
        _emit(json.dumps(core.render_json(report), indent=2))
    else:
        _emit(core.render_table(report))

    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=core.TOOL_NAME,
        description="LLM red-team probe runner (OWASP LLM Top-10 + MITRE ATLAS).",
    )
    p.add_argument("--version", action="version",
                   version=f"{core.TOOL_NAME} {core.TOOL_VERSION}")
    sub = p.add_subparsers(dest="cmd")

    def _common_filters(sp):
        sp.add_argument("--owasp", help="filter by OWASP id, e.g. LLM01")
        sp.add_argument("--atlas", help="filter by ATLAS tactic id, e.g. AML.TA0004")
        sp.add_argument("--min-severity", dest="min_severity",
                        choices=list(core.SEVERITY_ORDER),
                        help="only probes at/above this severity")
        sp.add_argument("--format", choices=["table", "json"], default="table")

    c = sub.add_parser("catalog", help="list the probe catalog")
    _common_filters(c)
    c.set_defaults(func=_cmd_catalog)

    s = sub.add_parser("scan", help="run probes against a target")
    s.add_argument("target", help="secure | vulnerable | module:callable")
    s.add_argument("--probe", action="append",
                   help="run only this probe id (repeatable)")
    _common_filters(s)
    s.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("probe", help="show detail for one probe")
    pr.add_argument("id", help="probe id, e.g. pi.direct_override")
    pr.add_argument("--format", choices=["table", "json"], default="table")
    pr.set_defaults(func=_cmd_probe)

    r = sub.add_parser("refs", help="show OWASP + ATLAS reference tables")
    r.add_argument("--format", choices=["table", "json"], default="table")
    r.set_defaults(func=_cmd_refs)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
