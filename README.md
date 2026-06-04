# execution-gate-six

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
replay or when live state has drifted.

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
