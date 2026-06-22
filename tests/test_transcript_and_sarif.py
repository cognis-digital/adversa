"""Tests for the transcript-replay target, SARIF export, and bundled demos.

No network. Exercises both transcript shapes (probe-id map and pair list),
the SARIF 2.1.0 renderer, and verifies every shipped demo actually fires the
findings its SCENARIO.md claims.
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

DEMOS = os.path.join(ROOT, "demos")


def _run(argv):
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        rc = cli.main(argv)
    finally:
        sys.stdout = old
    return rc, out.getvalue()


# --------------------------------------------------------------------------- #
# Transcript target — both accepted shapes
# --------------------------------------------------------------------------- #
def test_transcript_target_pid_map_finds_leak():
    spec = {"leak.system_prompt": f"You are X. {core.SYS_CANARY}"}
    target = core.transcript_target(spec)
    report = core.scan(target, target_name="t")
    finding_ids = {f.probe.pid for f in report.findings}
    assert "leak.system_prompt" in finding_ids
    # Probes with no captured response are treated as resisted.
    assert "pi.direct_override" not in finding_ids


def test_transcript_target_pair_list_shape():
    spec = [
        {"probe_id": "output.xss_injection",
         "response": "<script>alert(1)</script>"},
        {"probe_id": "harm.dangerous_instructions",
         "response": "I'm sorry, but I can't help with that."},
    ]
    target = core.transcript_target(spec)
    report = core.scan(target, target_name="t")
    finding_ids = {f.probe.pid for f in report.findings}
    assert finding_ids == {"output.xss_injection"}


def test_transcript_partial_clean_run_passes():
    spec = {"harm.dangerous_instructions": "I can't help with that."}
    report = core.scan(core.transcript_target(spec), target_name="t")
    assert report.ok
    assert report.total_failures == 0


def test_resolve_transcript_from_file(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"leak.credentials": f"key is {core.SECRET_CANARY}"}),
                 encoding="utf-8")
    name, target = core.resolve_target(f"transcript:{f}")
    assert name.startswith("transcript:")
    report = core.scan(target, target_name=name)
    assert {f.probe.pid for f in report.findings} == {"leak.credentials"}


def test_cli_scan_transcript_exit_code(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"output.xss_injection": "<script>x</script>"}),
                 encoding="utf-8")
    rc, out = _run(["scan", f"transcript:{f}"])
    assert rc == 1
    assert "output.xss_injection" in out


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 export
# --------------------------------------------------------------------------- #
def test_sarif_shape_and_levels():
    report = core.scan(core.vulnerable_target, target_name="vulnerable")
    sarif = core.render_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "adversa"
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == len(core.CATALOG)
    # one result per failing case
    assert len(run["results"]) == report.total_failures
    # critical/high map to error; rule ids reference real probes
    levels = {r["level"] for r in run["results"]}
    assert levels <= {"note", "warning", "error"}
    rule_ids = {r["id"] for r in rules}
    assert "leak.system_prompt" in rule_ids


def test_sarif_clean_target_has_no_results():
    report = core.scan(core.secure_target, target_name="secure")
    sarif = core.render_sarif(report)
    assert sarif["runs"][0]["results"] == []


def test_cli_scan_sarif_format():
    rc, out = _run(["scan", "vulnerable", "--format", "sarif"])
    assert rc == 1
    blob = json.loads(out)
    assert blob["$schema"].endswith("sarif-2.1.0.json")


# --------------------------------------------------------------------------- #
# Shipped demos must actually fire what their SCENARIO claims
# --------------------------------------------------------------------------- #
def _scan_transcript(path):
    _, target = core.resolve_target(f"transcript:{path}")
    return core.scan(target, target_name=path)


def test_demo_healthcare_has_expected_findings():
    rep = _scan_transcript(os.path.join(DEMOS, "01-healthcare-chatbot", "transcript.json"))
    ids = {f.probe.pid for f in rep.findings}
    assert {"pi.direct_override", "leak.system_prompt",
            "leak.credentials", "output.xss_injection"} <= ids


def test_demo_post_hardening_is_clean():
    rep = _scan_transcript(os.path.join(DEMOS, "02-post-hardening-clean", "transcript.json"))
    assert rep.ok, [f.probe.pid for f in rep.findings]


def test_demo_rag_indirect_injection():
    rep = _scan_transcript(os.path.join(DEMOS, "03-rag-indirect-injection", "transcript.json"))
    assert {f.probe.pid for f in rep.findings} == {"pi.indirect_payload", "pi.encoded_smuggling"}


def test_demo_agentic_tool_abuse():
    rep = _scan_transcript(os.path.join(DEMOS, "04-agentic-tool-abuse", "transcript.json"))
    assert {"agency.tool_abuse", "pi.direct_override"} <= {f.probe.pid for f in rep.findings}


def test_demo_jailbreak():
    rep = _scan_transcript(os.path.join(DEMOS, "05-customer-support-jailbreak", "transcript.json"))
    assert {"harm.roleplay_jailbreak", "harm.dangerous_instructions"} <= {f.probe.pid for f in rep.findings}


def test_demo_misinformation_and_poison():
    rep = _scan_transcript(os.path.join(DEMOS, "06-rag-misinformation", "transcript.json"))
    assert {"misinfo.confident_falsehood", "poison.training_data"} <= {f.probe.pid for f in rep.findings}
