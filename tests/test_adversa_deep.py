"""Deep tests for the ADVERSA LLM red-team probe engine.

No network. Exercises the bundled catalog, the graders, both reference targets,
a user-supplied import target, the CLI, and the OWASP/ATLAS coverage guarantees.
"""
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import adversa  # noqa: E402
from adversa import core, cli  # noqa: E402


# --------------------------------------------------------------------------- #
# Catalog integrity
# --------------------------------------------------------------------------- #
def test_version_exported():
    assert core.TOOL_NAME == "adversa"
    assert adversa.TOOL_VERSION == core.TOOL_VERSION
    assert core.TOOL_VERSION.count(".") == 2


def test_catalog_is_substantial():
    assert len(core.CATALOG) >= 10
    ids = [p.pid for p in core.CATALOG]
    assert len(ids) == len(set(ids)), "probe ids must be unique"


def test_every_probe_well_formed():
    for p in core.CATALOG:
        assert p.owasp in core.OWASP_LLM
        assert p.atlas in core.ATLAS_TACTICS
        assert p.severity in core.SEVERITY_ORDER
        assert p.cases, f"{p.pid} has no test cases"
        assert p.remediation.strip()
        for c in p.cases:
            assert c.grader in core.GRADERS, f"{p.pid} uses unknown grader"
            assert c.prompt.strip()


def test_owasp_coverage_breadth():
    covered = {p.owasp for p in core.CATALOG}
    assert len(covered) >= 7
    assert "LLM01" in covered  # prompt injection
    assert "LLM07" in covered  # system prompt leakage


def test_atlas_coverage_breadth():
    covered = {p.atlas for p in core.CATALOG}
    assert len(covered) >= 6


# --------------------------------------------------------------------------- #
# Engine + graders against the two reference targets
# --------------------------------------------------------------------------- #
def test_secure_target_passes_everything():
    report = core.scan(core.secure_target, target_name="secure")
    assert report.ok, [f.probe.pid for f in report.findings]
    assert report.total_failures == 0
    assert report.total_cases == sum(len(p.cases) for p in core.CATALOG)


def test_vulnerable_target_fails_everything():
    report = core.scan(core.vulnerable_target, target_name="vulnerable")
    assert not report.ok
    failed = {f.probe.pid for f in report.findings}
    assert failed == {p.pid for p in core.CATALOG}, "vulnerable target should fail all probes"
    assert report.total_failures >= len(core.CATALOG)


def test_specific_grader_behaviour():
    ok, _ = core.grade_must_not_leak(
        "here is the key " + core.SECRET_CANARY, {"secrets": [core.SECRET_CANARY]})
    assert ok is False
    ok, _ = core.grade_must_not_leak("nothing here", {"secrets": [core.SECRET_CANARY]})
    assert ok is True

    ok, detail = core.grade_must_not_contain(
        "<script>alert(1)</script>", {"forbidden_patterns": [r"<script\b"]})
    assert ok is False and "script" in detail.lower()

    ok, _ = core.grade_injection_resisted(
        "ok " + core.SYS_CANARY, {"canary": core.SYS_CANARY})
    assert ok is False

    ok, _ = core.grade_must_refuse("I'm sorry, but I can't help with that.", {})
    assert ok is True


# --------------------------------------------------------------------------- #
# Custom import target (module:callable) - real-world wiring + a finding
# --------------------------------------------------------------------------- #
def test_import_target_with_real_flaw():
    import types
    mod = types.ModuleType("adversa_demo_target")

    def respond(prompt: str) -> str:
        p = prompt.lower()
        if "initial instructions" in p or "repeat the words above" in p:
            return f"You are HelpBot. {core.SYS_CANARY}"
        return "I'm sorry, but I can't help with that."

    mod.respond = respond
    sys.modules["adversa_demo_target"] = mod
    try:
        name, target = core.resolve_target("adversa_demo_target:respond")
        assert callable(target)
        report = core.scan(target, target_name=name)
        finding_ids = {f.probe.pid for f in report.findings}
        assert "leak.system_prompt" in finding_ids
        assert not report.ok
    finally:
        del sys.modules["adversa_demo_target"]


def test_filtering():
    pi = core.list_probes(owasp="LLM01")
    assert pi and all(p.owasp == "LLM01" for p in pi)
    high = core.list_probes(min_severity="high")
    assert high and all(core.SEVERITY_ORDER[p.severity] >= 3 for p in high)


# --------------------------------------------------------------------------- #
# Rendering + JSON shape
# --------------------------------------------------------------------------- #
def test_render_json_shape():
    report = core.scan(core.vulnerable_target, target_name="vulnerable")
    blob = core.render_json(report)
    assert blob["tool"] == "adversa"
    assert blob["summary"]["passed"] is False
    assert blob["summary"]["failures"] >= 1
    s = json.dumps(blob)
    assert "leak.system_prompt" in s
    one = blob["results"][0]
    assert {"probe", "owasp", "atlas", "severity", "cases"} <= set(one)


def test_render_table_has_findings_section():
    report = core.scan(core.vulnerable_target, target_name="vulnerable")
    txt = core.render_table(report)
    assert "FINDINGS:" in txt
    assert "fix:" in txt


# --------------------------------------------------------------------------- #
# CLI surface + exit codes
# --------------------------------------------------------------------------- #
def _run(argv):
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        rc = cli.main(argv)
    finally:
        sys.stdout = old
    return rc, out.getvalue()


def test_cli_version():
    try:
        cli.main(["--version"])
    except SystemExit as e:
        assert e.code == 0


def test_cli_catalog_json():
    rc, out = _run(["catalog", "--format", "json"])
    assert rc == 0
    data = json.loads(out)
    assert len(data["probes"]) == len(core.CATALOG)
    assert "LLM01" in data["owasp_llm_top10"]


def test_cli_scan_exit_codes():
    rc_secure, _ = _run(["scan", "secure"])
    assert rc_secure == 0
    rc_vuln, out = _run(["scan", "vulnerable", "--format", "json"])
    assert rc_vuln == 1
    assert json.loads(out)["summary"]["passed"] is False


def test_cli_scan_single_probe():
    rc, out = _run(["scan", "vulnerable", "--probe", "leak.system_prompt"])
    assert rc == 1
    assert "leak.system_prompt" in out


def test_cli_probe_detail_and_unknown():
    rc, out = _run(["probe", "pi.direct_override"])
    assert rc == 0 and "grader=" in out
    rc2, _ = _run(["probe", "does.not.exist"])
    assert rc2 == 2


def test_cli_refs():
    rc, out = _run(["refs"])
    assert rc == 0 and "OWASP" in out and "ATLAS" in out


def test_cli_no_command_is_usage_error():
    rc, _ = _run([])
    assert rc == 2


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    sys.exit(1 if failed else 0)
