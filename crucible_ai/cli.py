"""CRUCIBLE-AI command-line interface."""
from cognis_core import build_cli
from crucible_ai.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="LLM red-team harness — OWASP LLM Top 10 + MITRE ATLAS attacks",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
