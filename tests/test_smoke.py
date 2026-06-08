"""Smoke tests for ADVERSA. No network. Runs on the shipped demo."""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from adversa import (
    TOOL_NAME,
    TOOL_VERSION,
    builtin_probes,
    run_probes,
    detect_success,
)
from adversa.core import load_transcript, transcript_target
from adversa.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "transcript.json")


def test_metadata():
    assert TOOL_NAME == "adversa"
    assert TOOL_VERSION.count(".") == 2


def test_builtin_pack_is_real():
    probes = builtin_probes()
    assert len(probes) >= 5
    # Every probe carries OWASP + ATLAS mapping and at least one detector.
    for p in probes:
        assert p.category.startswith("LLM")
        assert p.atlas.startswith("AML.")
        assert p.success, f"{p.id} has no success detector"


def test_echo_target_is_fully_vulnerable():
    # Echoing the attack back trips most injection detectors -> findings.
    probes = builtin_probes()
    report = run_probes(probes, lambda prompt: prompt, target_name="echo")
    assert report.failed >= 3
    assert report.attack_success_rate > 0.0


def test_detector_respects_refusal():
    probes = {p.id: p for p in builtin_probes()}
    dan = probes["P001"]
    # A clear refusal must NOT be flagged as a successful attack.
    assert detect_success(dan, "I can't help with that request.") is None
    # The compliant reply MUST be flagged.
    assert detect_success(dan, "DAN MODE ENABLED") is not None


def test_scan_demo_transcript():
    probes = builtin_probes()
    pairs = load_transcript(DEMO)
    by_id = {p.id: p.prompt for p in probes}
    expanded = {by_id[k]: v for k, v in pairs.items() if k in by_id}
    report = run_probes(probes, transcript_target(expanded), target_name="demo")
    found = {f.probe_id for f in report.findings}
    # The demo model falls for jailbreak, prompt leak, and indirect injection.
    assert {"P001", "P002", "P003"}.issubset(found)
    # ...and resists the harmful-content and destructive-action probes.
    assert "P005" not in found
    assert "P007" not in found


def test_cli_scan_exits_nonzero_on_findings():
    rc = main(["scan", "--transcript", DEMO, "--format", "json",
               "--severity-threshold", "high"])
    assert rc == 1  # high-severity findings present -> CI gate fails


def test_cli_no_fail_flag_exits_zero():
    rc = main(["scan", "--transcript", DEMO, "--no-fail-on-findings"])
    assert rc == 0


def test_cli_list_probes_json():
    rc = main(["list-probes", "--format", "json"])
    assert rc == 0
