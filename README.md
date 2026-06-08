# ADVERSA — LLM red-team harness — OWASP LLM Top 10 + MITRE ATLAS attack packs

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-adversa.svg)](https://pypi.org/project/cognis-adversa/)
[![CI](https://github.com/cognis-digital/adversa/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/adversa/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**LLM red-team harness — OWASP LLM Top 10 + MITRE ATLAS attack packs.**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

## Why

Security and intelligence teams need lLM red-team harness — OWASP LLM Top 10 + MITRE ATLAS attack packs without standing up heavyweight infrastructure. `adversa` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

## Install

```bash
pip install cognis-adversa
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
adversa --version
adversa scan demos/                      # run against the bundled demo
adversa scan demos/ --format sarif --out r.sarif --fail-on high
adversa scan demos/ --format html --out report.html
adversa mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-healthcare-chatbot/`](demos/01-healthcare-chatbot/SCENARIO.md)
- [`demos/02-post-hardening/`](demos/02-post-hardening/SCENARIO.md)
- [`demos/03-enterprise-mixed-rag/`](demos/03-enterprise-mixed-rag/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## Credits / Built on

Cognis composes and credits the best of open source. This tool builds on / interoperates with:

- [`leondz/garak`](https://github.com/leondz/garak) — probe library (NVIDIA)
- [`Azure/PyRIT`](https://github.com/Azure/PyRIT) — risk-identification framework
- [`promptfoo/promptfoo`](https://github.com/promptfoo/promptfoo) — eval harness reference
- [`confident-ai/deepteam`](https://github.com/confident-ai/deepteam) — red-team packs

Missing a credit? Open a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How it fits the Cognis Neural Suite

`adversa` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `ai-security`:** [`aegis`](https://github.com/cognis-digital/aegis), [`promptmirror`](https://github.com/cognis-digital/promptmirror), [`ledgermind`](https://github.com/cognis-digital/ledgermind), [`guardpost`](https://github.com/cognis-digital/guardpost), [`hallumark`](https://github.com/cognis-digital/hallumark), [`aicard`](https://github.com/cognis-digital/aicard), [`biascope`](https://github.com/cognis-digital/biascope), [`mcpharden`](https://github.com/cognis-digital/mcpharden), [`agentlog`](https://github.com/cognis-digital/agentlog), [`ragshield`](https://github.com/cognis-digital/ragshield)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
