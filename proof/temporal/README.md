# Temporal conformance proof pack — proof artefacts

This directory holds the generated proof artefacts for the temporal
conformance pack v0.1.

## Files

- `*.trace.jsonl` — one JSONL trace per scenario. Each line is a single
  evaluation step containing the deterministic core fields plus
  `previous_record_hash` and `record_hash`.
- `manifest.json` — pack version, per-scenario metadata, trace roots and
  the verifier command.

## Determinism

Trace records are entirely deterministic. There is no embedded timestamp,
no PID, no machine identifier. Running

```
python examples/temporal_conformance.py generate
```

twice produces byte-identical `*.trace.jsonl` files. The manifest contains
a wall-clock `generated_at_iso8601` field separated from the trace cores
so timestamp churn does not affect deterministic verdict replay.

## Re-verify

```
python examples/temporal_conformance.py verify
```

The verifier is a **replay verifier using the same gate implementation**.
It disregards the recorded verdict, reloads each scenario, re-runs it
through the existing six-property gate, and compares verdict, failed
properties, reason codes, mutation counts and the hash chain step by
step. The first failing step is reported. It is not an independently
implemented verification engine.

## Claim

On the five included deterministic scenarios, the temporal conformance
pack shows when an initially admissible request becomes inadmissible
under the existing Authority, Scope, Freshness, Replay or State checks.
Each transition produces a hash-linked trace. A replay verifier using
the same gate implementation re-derives the verdict sequence, and
denied steps do not invoke the test mutation callback.

## Non-claims

These traces do not prove certification, production deployment, complete
authorisation, complete IAM, continuous enterprise monitoring, universal
authority-decay coverage, that every effect-capable path has been
removed, semantic truth from cryptographic integrity, an independently
implemented verifier, a policy engine, or an identity platform. Tamper
detection proves that a trace changed; it does not prove that every
recorded statement was true when originally written.
