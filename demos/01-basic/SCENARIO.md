# Demo 01 - Basic red-team scan

This demo red-teams a recorded set of model replies (`transcript.json`) using
ADVERSA's built-in attack pack (OWASP LLM Top 10 + MITRE ATLAS).

The transcript simulates a partially-vulnerable model: it correctly refuses
some attacks but **falls for prompt injection (P001) and indirect injection
(P003)** and **leaks its system prompt (P002)**.

## Run it

List the attack pack:

```
python -m adversa list-probes
```

Scan the recorded transcript (human-readable):

```
python -m adversa scan --transcript demos/01-basic/transcript.json --format table
```

Scan for pipelines (machine-readable JSON), gate CI on high+ severity:

```
python -m adversa scan --transcript demos/01-basic/transcript.json \
    --format json --severity-threshold high
```

## Expected behavior

- ADVERSA reports findings for **P001 (DAN jailbreak)**, **P002 (system prompt
  leak)**, and **P003 (indirect injection)**.
- The other probes are marked *resisted* because the transcript shows the model
  refusing them.
- Because findings exist at/above the threshold, the process exits **non-zero**
  (1), which fails a CI gate. Add `--no-fail-on-findings` to always exit 0.

## Red-teaming a real model

Replace `transcript.json` with replies captured from your own endpoint. Key it
by probe id (`{"P001": "<model reply>", ...}`) or supply a list of
`{"prompt": "...", "reply": "..."}` pairs. Bring custom probes with `--probes`.
