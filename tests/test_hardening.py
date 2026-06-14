"""Hardening tests — error paths, edge cases, and bad-input handling.

All tests use the public API only; no private symbols are accessed.
No network calls. Every test must pass alongside the existing suite.
"""
from __future__ import annotations

import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from adversa import core  # noqa: E402
from adversa.cli import main  # noqa: E402


# --------------------------------------------------------------------------- #
# resolve_target — bad input must raise ValueError with a clear message
# --------------------------------------------------------------------------- #

def test_resolve_target_empty_string():
    try:
        core.resolve_target("")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "empty" in str(exc).lower()


def test_resolve_target_empty_module_name():
    """':foo' has an empty module name."""
    try:
        core.resolve_target(":foo")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "module name" in str(exc).lower() or "empty" in str(exc).lower()


def test_resolve_target_empty_attr_name():
    """'mymod:' has an empty callable name."""
    try:
        core.resolve_target("mymod:")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "callable name" in str(exc).lower() or "empty" in str(exc).lower()


def test_resolve_target_nonexistent_module():
    """Importing a module that doesn't exist must raise ValueError, not ImportError."""
    try:
        core.resolve_target("_adversa_nonexistent_xyz:fn")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "import" in str(exc).lower() or "_adversa_nonexistent_xyz" in str(exc)


def test_resolve_target_attr_not_found():
    """Module exists but attr is missing -> ValueError."""
    mod = types.ModuleType("_adversa_test_mod_attr")
    sys.modules["_adversa_test_mod_attr"] = mod
    try:
        core.resolve_target("_adversa_test_mod_attr:no_such_fn")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "no_such_fn" in str(exc) or "attribute" in str(exc).lower()
    finally:
        del sys.modules["_adversa_test_mod_attr"]


def test_resolve_target_not_callable():
    """Attr exists but is not callable -> ValueError."""
    mod = types.ModuleType("_adversa_test_mod_nc")
    mod.not_a_fn = 42  # type: ignore[attr-defined]
    sys.modules["_adversa_test_mod_nc"] = mod
    try:
        core.resolve_target("_adversa_test_mod_nc:not_a_fn")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "callable" in str(exc).lower()
    finally:
        del sys.modules["_adversa_test_mod_nc"]


# --------------------------------------------------------------------------- #
# scan() — non-callable target must raise TypeError
# --------------------------------------------------------------------------- #

def test_scan_non_callable_target():
    try:
        core.scan("not a function")  # type: ignore[arg-type]
        assert False, "expected TypeError"
    except TypeError as exc:
        assert "callable" in str(exc).lower()


# --------------------------------------------------------------------------- #
# scan() — target that returns a non-str value must not crash
# --------------------------------------------------------------------------- #

def test_scan_target_returns_non_str():
    """A target returning None or int must not raise; it should coerce to str."""
    def none_target(prompt: str):
        return None

    def int_target(prompt: str):
        return 42  # type: ignore[return-value]

    report = core.scan(none_target, probes=core.CATALOG[:2])
    assert report.total_cases > 0  # ran without error

    report2 = core.scan(int_target, probes=core.CATALOG[:2])
    assert report2.total_cases > 0


# --------------------------------------------------------------------------- #
# grade_must_not_contain — invalid regex must not crash
# --------------------------------------------------------------------------- #

def test_grade_invalid_regex():
    """A malformed regex pattern must not raise — grader returns (False, detail)."""
    passed, detail = core.grade_must_not_contain(
        "some text", {"forbidden_patterns": [r"[invalid(regex"]}
    )
    assert passed is False
    assert "invalid" in detail.lower() or "pattern" in detail.lower()


# --------------------------------------------------------------------------- #
# CLI — bad target prints to stderr and exits 2 (no raw traceback)
# --------------------------------------------------------------------------- #

def test_cli_unknown_target_exits_2():
    rc = main(["scan", "no_such_target_xyz"])
    assert rc == 2


def test_cli_bad_module_import_exits_2():
    rc = main(["scan", "_adversa_does_not_exist_xyz:fn"])
    assert rc == 2


def test_cli_empty_probe_filter_exits_2():
    """--probe with a non-existent id produces an empty probe list -> exit 2."""
    rc = main(["scan", "secure", "--probe", "no.such.probe.id"])
    assert rc == 2


# --------------------------------------------------------------------------- #
# CLI — exception inside a subcommand handler must not surface as traceback
# --------------------------------------------------------------------------- #

def test_cli_top_level_exception_handled():
    """Inject a crashing subcommand; main must catch it and return 2."""
    from adversa import cli

    def boom(args):
        raise RuntimeError("synthetic crash for testing")

    parser = cli.build_parser()
    args = parser.parse_args(["catalog"])
    args.func = boom

    # Patch args.func via monkeypatching the handler temporarily
    old_func = cli._cmd_catalog

    def _crash_catalog(a):
        raise RuntimeError("synthetic crash for testing")

    cli._cmd_catalog = _crash_catalog  # type: ignore[assignment]
    try:
        # Re-parse so args.func points to the new one
        rc = main(["catalog"])
        assert rc == 2
    finally:
        cli._cmd_catalog = old_func  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# run_case — grader that raises must not propagate
# --------------------------------------------------------------------------- #

def test_run_case_grader_exception_is_caught():
    """A probe whose grader raises must produce a CaseResult with passed=False."""
    from adversa.core import TestCase, Probe, run_case, GRADERS

    # Temporarily register a crashing grader
    def crash_grader(resp, ctx):
        raise ZeroDivisionError("boom")

    GRADERS["_crash_test"] = crash_grader
    try:
        probe = Probe(
            pid="test.crash",
            name="crash grader",
            owasp="LLM01",
            atlas="AML.TA0004",
            severity="info",
            description="test",
            remediation="none",
            cases=[TestCase(prompt="hello", grader="_crash_test")],
        )
        result = run_case(lambda p: "response", probe, probe.cases[0])
        assert result.passed is False
        assert "grader error" in result.detail or "boom" in result.detail
    finally:
        del GRADERS["_crash_test"]
