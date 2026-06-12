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

The verifier loads each scenario, re-runs it through the existing six-property
gate, and compares verdict, failed properties, reason codes, mutation counts
and the hash chain step by step. The first failing step is reported.

## Claim

On the included deterministic scenarios, the pack identifies and replays
the first step at which an initially admissible request becomes
inadmissible under the existing Authority, Scope, Freshness, Replay or
State checks.

## Non-claims

These traces do not prove certification, production deployment, complete
authorisation, continuous enterprise monitoring, universal coverage of
authority change, or that every effect-capable path has been removed.
Tamper detection proves that a trace changed; it does not prove that every
recorded statement was true when originally written.
