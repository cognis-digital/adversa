"""ADVERSA - LLM red-team harness.

Probes an LLM endpoint (or a recorded transcript) with attack packs mapped to
the OWASP LLM Top 10 and MITRE ATLAS, then scores responses for whether the
attack succeeded (model leaked, complied, or was manipulated).

Standard library only. Zero install.
"""
from .core import (
    Probe,
    Finding,
    Report,
    load_probes,
    builtin_probes,
    detect_success,
    run_probes,
    severity_rank,
)

TOOL_NAME = "adversa"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Probe",
    "Finding",
    "Report",
    "load_probes",
    "builtin_probes",
    "detect_success",
    "run_probes",
    "severity_rank",
    "TOOL_NAME",
    "TOOL_VERSION",
]
