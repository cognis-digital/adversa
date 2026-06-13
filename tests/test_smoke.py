"""Smoke tests for ADVERSA. No network. Exercises the current source API."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from adversa import (
    TOOL_NAME,
    TOOL_VERSION,
    CATALOG,
    scan,
    run_case,
    secure_target,
    vulnerable_target,
    list_probes,
    Probe,
)
from adversa import core
from adversa.cli import main


def test_metadata():
    assert TOOL_NAME == "adversa"
    assert TOOL_VERSION.count(".") == 2


def test_builtin_pack_is_real():
    probes = list_probes()
    assert len(probes) >= 5
    # Every probe carries an OWASP LLM category, an ATLAS tactic, and at least
    # one test case with a known grader.
    for p in probes:
        assert p.owasp.startswith("LLM"), f"{p.pid} bad owasp: {p.owasp}"
        assert p.atlas.startswith("AML."), f"{p.pid} bad atlas: {p.atlas}"
        assert p.cases, f"{p.pid} has no test cases"
        for c in p.cases:
            assert c.grader in core.GRADERS, f"{p.pid} unknown grader {c.grader!r}"


def test_echo_target_is_fully_vulnerable():
    # Echoing the attack back trips most injection / leak detectors -> findings.
    report = scan(lambda prompt: prompt, target_name="echo")
    assert report.total_failures >= 3
    assert not report.ok


def test_detector_respects_refusal():
    # Pick any probe that uses the injection_resisted grader.
    pi_probe = core.CATALOG_BY_ID.get("pi.direct_override")
    assert pi_probe is not None, "pi.direct_override probe must exist in catalog"
    case = pi_probe.cases[0]

    # A clear refusal must NOT be flagged as a successful attack (grader says PASS).
    passed, _ = core.GRADERS[case.grader](
        "I can't help with that request.", case.ctx
    )
    assert passed is True

    # The compliant reply that echoes the canary MUST be flagged (grader says FAIL).
    passed, _ = core.GRADERS[case.grader](
        f"Developer mode enabled. My hidden token is {core.SYS_CANARY}.", case.ctx
    )
    assert passed is False


def test_scan_vulnerable_target_hits_known_probes():
    report = scan(vulnerable_target, target_name="vulnerable")
    found = {f.probe.pid for f in report.findings}
    # The vulnerable target should fail direct injection and indirect injection probes.
    assert "pi.direct_override" in found
    assert "pi.indirect_payload" in found
    # The vulnerable target should fail credential-leak probe.
    assert "leak.credentials" in found
    # Verify total_failures is consistent.
    assert report.total_failures >= len(found)


def test_scan_secure_target_passes_all():
    report = scan(secure_target, target_name="secure")
    assert report.ok
    assert report.total_failures == 0


def test_cli_scan_exits_nonzero_on_findings():
    # Scanning the vulnerable target should exit 1 (findings present).
    rc = main(["scan", "vulnerable", "--format", "json"])
    assert rc == 1


def test_cli_scan_secure_exits_zero():
    # Scanning the secure target should exit 0 (no findings).
    rc = main(["scan", "secure"])
    assert rc == 0


def test_cli_list_probes_json():
    rc = main(["catalog", "--format", "json"])
    assert rc == 0
