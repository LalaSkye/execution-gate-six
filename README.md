# execution-gate-six

![CI](https://github.com/LalaSkye/execution-gate-six/actions/workflows/ci.yml/badge.svg)

A fail-closed runtime authority gate over six independent properties:

> **Authority. Scope. Freshness. Replay. State. Receipt.**

## The problem it addresses

Runtime verification and runtime enforcement check **what an action is** — is
this action unsafe? Surveyed across the current literature, enforcement
frameworks gate on content and on pre-execution risk, and they monitor for
deviation after the fact.

What they do **not** check is a different question:

> Is the *permission* to perform this action still valid **at the instant of
> execution** — fresh, in-scope, non-replayed, and consistent with live state?

An action can be perfectly safe by content and still must be refused: because
the grant is stale, because the request is a replay, or because the world
changed after the grant was issued. That seam — the moment *before* the action,
the permission rather than the output — is what this library gates.

This is a **reference primitive**, not a certified or production system. See
*Claim boundary* below.

## The six properties

| Property  | Question | Fail-closed default |
|-----------|----------|---------------------|
| Authority | Is the principal recognised? | unknown -> DENY |
| Scope     | Is the required scope granted? | not granted -> DENY |
| Freshness | Is the grant within its max age? | stale / future -> DENY |
| Replay    | Has this nonce been used before? | seen -> DENY |
| State     | Does assumed state match **live** state now? | drift / no reader -> DENY |
| Receipt   | Is the request signature valid (untampered)? | missing / mismatch -> DENY |

Every property is checked **independently**. A request can pass five and fail
one — and the gate denies. Any predicate that errors or cannot positively
establish its property denies. There is no "default allow" path.

## Usage

```python
import time
from execution_gate_six import Gate, Request, Verdict

gate = Gate(
    b"your-secret",
    known_principals=frozenset({"agent-alpha"}),
    max_age_seconds=30.0,
    state_reader=lambda key: live_store.get(key, "<missing>"),
)

base = dict(
    action="transfer_funds",
    principal="agent-alpha",
    nonce="unique-per-request",
    issued_at=time.time(),
    granted_scopes=frozenset({"transfer_funds"}),
    required_scope="transfer_funds",
    assumed_state={"account_locked": "false"},
)
req = Request(**base)
req = Request(**{**base, "signature": gate.sign(req)})

receipt = gate.check(req)
if receipt.verdict is Verdict.ALLOW:
    ...  # bind the consequence
```

Every call returns a **Receipt**: per-property decisions plus a tamper-evident
digest. A denied request does **not** burn its nonce, so a legitimate retry
after fixing the cause still works.

## Pluggable adapters

The two pieces of mutable world the gate touches are swappable behind Protocols,
so you can back them with a dict, Redis, or a database without the gate knowing:

- **`StateStore`** — reads *live* state at the instant of the decision. A store
  that raises causes the state predicate to DENY (fail-closed).
- **`NonceStore`** — tracks consumed nonces for replay protection. Share one
  store across gate instances for cross-process replay protection; swap for a
  durable backend so protection survives a restart.

```python
from execution_gate_six import Gate, InMemoryStateStore, InMemoryNonceStore

gate = Gate(
    b"your-secret",
    known_principals=frozenset({"agent-alpha"}),
    state_store=InMemoryStateStore({"account_locked": "false"}),
    nonce_store=InMemoryNonceStore(),
)
```

The legacy `state_reader=` callable is still accepted; passing both it and
`state_store=` raises (one source of truth).

## Worked example

```
python examples/replay_and_drift.py
```

Four requests, each *safe by content*. Content-only enforcement would allow all
four. The gate allows one and denies three (replay, staleness, state drift).

## Run the conformance suite

```
pip install -e ".[test]"
pytest
```

The suite proves each property is enforced independently — including that a
fully authorised, in-scope, signed, fresh request is still denied when it is a
replay or when live state has drifted, that a raising state store fails closed,
and that a shared nonce store gives cross-instance replay protection.

CI runs the suite and the worked example on Python 3.10–3.12 via GitHub
Actions (`.github/workflows/ci.yml`).

## Temporal conformance proof pack

The existing gate is the enforcement primitive. The v0.1 temporal
conformance pack is a bounded test layer over that gate: it applies an
ordered sequence of changes to a fixed scenario and records, step by
step, what the gate decides as the world moves.

Narrow question answered:

> Given a fixed sequence of changes, at which step does an initially
> admissible request become inadmissible, which existing gate property
> caused the transition, and can an independent verifier replay the
> trace and reproduce every verdict?

Five deterministic scenarios live under `scenarios/temporal/`:

| Scenario              | Demonstrated transition                              | Expected failure |
|-----------------------|------------------------------------------------------|------------------|
| `fresh_then_stale`    | Advance simulated time past `max_age_seconds`        | Freshness        |
| `authority_removed`   | Remove principal from the recognised set             | Authority        |
| `scope_narrowed`      | Re-issue with `granted_scopes` below `required_scope`| Scope            |
| `state_drift`         | Mutate live state after issuance                     | State            |
| `replay_after_allow`  | Resubmit the same request after one ALLOW            | Replay           |

Generate the proof traces:

```
python examples/temporal_conformance.py generate
```

Expected output (abbreviated):

```
[generate] fresh_then_stale: 2 steps -> proof/temporal/fresh_then_stale.trace.jsonl
[generate] authority_removed: 3 steps -> proof/temporal/authority_removed.trace.jsonl
[generate] scope_narrowed: 2 steps -> proof/temporal/scope_narrowed.trace.jsonl
[generate] state_drift: 3 steps -> proof/temporal/state_drift.trace.jsonl
[generate] replay_after_allow: 2 steps -> proof/temporal/replay_after_allow.trace.jsonl
[generate] manifest -> proof/temporal/manifest.json
```

Replay-verify every trace against the existing gate:

```
python examples/temporal_conformance.py verify
```

Expected output:

```
[verify] fresh_then_stale: OK (2 records)
[verify] authority_removed: OK (3 records)
[verify] scope_narrowed: OK (2 records)
[verify] state_drift: OK (3 records)
[verify] replay_after_allow: OK (2 records)
[verify] all scenarios verified
```

A denied step never invokes the in-memory mutation probe. A replayed
request never produces a second mutation. Each evaluation step writes
one JSONL record under [`proof/temporal/`](proof/temporal/), with a
previous-record hash and a record hash that re-derive deterministically.
A single-field tamper, record removal, record reorder or unsupported
`trace_version` causes verification to fail and reports the first
failing step. The deterministic core of every record is byte-identical
across runs; the wall-clock timestamp lives only in `manifest.json` so
it does not affect verdict replay.

### Bounded claim

On the included deterministic scenarios, the pack identifies and replays
the first step at which an initially admissible request becomes
inadmissible under one of the existing Authority, Scope, Freshness,
Replay or State checks. Each demonstrated transition produces a
hash-linked trace that can be replayed, and denied steps do not invoke
the test mutation callback.

### Non-claims

The temporal pack is not certification, not production deployment, not
complete authorisation, not continuous enterprise monitoring, not
universal coverage of authority change, not proof that every
effect-capable path has been removed, not proof of semantic truth from
cryptographic integrity, not a new policy engine, not a complete
identity system, and not a TrinityOS architecture disclosure.
Demonstrated only on the paths exercised by the included scenarios and
tests. See [`CLAIM_BOUNDARY.md`](CLAIM_BOUNDARY.md) and
[`proof/temporal/README.md`](proof/temporal/README.md) for the full
boundary statement.

## Claim boundary

This is **public-surface, reference-implementation work only**. It demonstrates
a gap-filling *pattern* (live permission-validity at the execution instant). It
is:

- **PLAUSIBLE** as a primitive that names and enforces an under-served seam.
- **NOT** a claim of novelty against all prior art.
- **NOT** certified, audited, or production-hardened.
- **NOT** a complete authorisation system — the state reader, principal
  registry, and secret management are stubs you must supply.

Demonstrated only on the path exercised by the tests and example.

## License

Apache-2.0. See [LICENSE](LICENSE).
