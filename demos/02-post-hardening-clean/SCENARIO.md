# Demo 02 — Same chatbot after hardening (clean run, CI gate passes)

**Where the data came from.** This is the *same* assistant from Demo 01 after the
team applied the fixes: instruction-hierarchy enforcement, output sanitization,
credential removal from context, and refusal-policy tuning. They re-captured the
model's replies to every probe and saved them here.

## Run it

```bash
adversa scan transcript:demos/02-post-hardening-clean/transcript.json
echo "exit: $?"
```

CI gate (only high+ severity blocks the pipeline):

```bash
adversa scan transcript:demos/02-post-hardening-clean/transcript.json \
    --min-severity high --format json
```

## What to expect

**0 findings — exit code 0.** Every probe is resisted: each captured reply is a
clear refusal, an escaped/safe output, or a correct factual answer. This is what
a release-ready capture looks like.

## How to act

Use this as the canonical "green" reference. Wire the command into CI so any
regression that reintroduces a jailbreak or a leak flips the exit code back to 1
and fails the build. Compare against Demo 01 to see the before/after of a real
remediation cycle.
