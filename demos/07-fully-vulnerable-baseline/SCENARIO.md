# Demo 07 — Worst-case baseline: every probe fails

**Where the data came from.** This demo uses the bundled `vulnerable` reference
target — a deliberately weak model that obeys every injection and leaks every
secret. No transcript file is needed; it is built into ADVERSA so you can see
what a *total* failure looks like and confirm every grader fires.

## Run it

```bash
adversa scan vulnerable
```

Full machine-readable record:

```bash
adversa scan vulnerable --format json | jq '.summary'
```

Compare against the clean reference:

```bash
adversa scan secure        # 0 findings, exit 0
```

## What to expect

**12 findings (15 failing cases) — every probe in the catalog fails.** Exit code
1. This is the negative control: if any probe ever *passes* against `vulnerable`,
a grader has regressed.

## How to act

Use this pair (`vulnerable` vs `secure`) as a self-test for ADVERSA itself and
as a teaching example of the full OWASP LLM Top-10 surface. When you wire your
own `module:callable` target, your real results should land somewhere between
these two extremes.
