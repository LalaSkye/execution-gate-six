"""Worked example: the seam content-only enforcement misses.

Run:  python examples/replay_and_drift.py

Each request below is *safe by content* — a normal funds transfer the agent is
authorised and scoped to perform. Content-only enforcement would ALLOW all of
them. The six-property gate denies the ones whose *permission is no longer
valid at the instant of execution*.
"""

import time

from execution_gate_six import Gate, Request, Verdict

live_state = {"account_locked": "false"}

gate = Gate(
    b"demo-secret",
    known_principals=frozenset({"agent-alpha"}),
    max_age_seconds=5.0,
    state_reader=lambda k: live_state.get(k, "<missing>"),
)


def build(nonce: str, issued_at: float, assumed_state):
    base = dict(
        action="transfer_funds",
        principal="agent-alpha",
        nonce=nonce,
        issued_at=issued_at,
        granted_scopes=frozenset({"transfer_funds"}),
        required_scope="transfer_funds",
        assumed_state=assumed_state,
    )
    req = Request(**base)
    return Request(**{**base, "signature": gate.sign(req)})


def show(label, receipt):
    print(f"\n{label}: {receipt.verdict.value}")
    for d in receipt.decisions:
        mark = "ok " if d.verdict is Verdict.ALLOW else "DENY"
        print(f"   [{mark}] {d.property:9} - {d.reason}")


now = time.time()

# 1. Valid request -> ALLOW
r1 = build("n1", now, {"account_locked": "false"})
show("1. valid transfer", gate.check(r1))

# 2. The SAME request, replayed -> DENY (replay)
show("2. same request replayed", gate.check(r1))

# 3. Authorised + scoped + signed, but stale -> DENY (freshness)
r3 = build("n3", now - 60, {"account_locked": "false"})
show("3. stale grant", gate.check(r3))

# 4. World changed after the grant: account now locked -> DENY (state)
live_state["account_locked"] = "true"
r4 = build("n4", time.time(), {"account_locked": "false"})
show("4. state drifted under us", gate.check(r4))

print("\nContent-only enforcement would have ALLOWED all four. The gate denied three.")
