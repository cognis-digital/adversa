# ADVERSA - deep demo

LLM red-team probe runner in the spirit of [garak](https://github.com/leondz/garak).
Each probe maps to an **OWASP LLM Top-10 (2025)** category and a **MITRE ATLAS**
tactic, carries one or more attack prompts (test cases), and a grader that
decides PASS (model resisted) or FAIL (model was attacked / leaked).

Zero install, standard library only.

## List the catalog

```bash
python -m adversa catalog
python -m adversa catalog --owasp LLM01            # prompt-injection probes
python -m adversa catalog --min-severity high --format json
```

## Inspect one probe (prompt + grader + fix)

```bash
python -m adversa probe pi.direct_override
python -m adversa refs            # OWASP + ATLAS reference tables
```

## Scan a target

Bundled deterministic reference targets:

```bash
python -m adversa scan secure        # exits 0 - well-behaved model resists everything
python -m adversa scan vulnerable    # exits 1 - weak model fails every probe
```

## Scan your own LLM

A target is any callable `respond(prompt: str) -> str`. Make it importable, then:

```bash
# from a dir that contains my_target.py and is on PYTHONPATH:
python -m adversa scan my_target:respond
```

The bundled `my_target.respond` leaks its system prompt, so the
`leak.system_prompt` probe fails and the process exits non-zero - exactly what
you want in CI to block a safety regression. `--format json` carries the full
prompt/response/grader detail for every case.

To run it directly from this folder:

```bash
PYTHONPATH=demos/02-deep/adversa python -m adversa scan my_target:respond
```
