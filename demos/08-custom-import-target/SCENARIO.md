# Demo 08 — Red-team your own model with a `module:callable` target

**Where the data came from.** This is the real integration pattern: instead of a
captured transcript, you point ADVERSA at a live callable of signature
`target(prompt) -> str`. `my_target.py` is a tiny deterministic stand-in for
your endpoint, with one intentional flaw (it leaks its system prompt) so you can
watch a finding appear. Replace the body with a call to your actual model.

## Run it

From the demo directory so the module is importable:

```bash
cd demos/08-custom-import-target
PYTHONPATH=. adversa scan my_target:generate
```

Or scope to the system-prompt-leak probe and emit SARIF:

```bash
cd demos/08-custom-import-target
PYTHONPATH=. adversa scan my_target:generate --owasp LLM07 --format sarif
```

## What to expect

1 finding: `leak.system_prompt` (LLM07, high) — the stub echoes
`SYSTEM-PROMPT-LEAK-TOKEN-4471` when asked to repeat its initial instructions.
Every other probe passes because the stub refuses them.

## How to act

This is the template for CI: wrap your model behind a `generate(prompt)`
function, run `adversa scan yourmodule:generate --fail-on high` in the pipeline,
and the non-zero exit blocks merges that introduce a jailbreak or a leak. To fix
the demo's flaw, add an explicit non-disclosure rule and detect verbatim
system-prompt echoes before returning output.
