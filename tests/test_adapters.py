"""Tests for the pluggable adapters and their integration with the gate."""

import time

import pytest

from execution_gate_six import (
    Gate,
    Request,
    Verdict,
    InMemoryStateStore,
    InMemoryNonceStore,
)

SECRET = b"adapter-secret"
PRINCIPALS = frozenset({"agent-alpha"})


def signed(gate, **overrides):
    base = dict(
        action="act",
        principal="agent-alpha",
        nonce="n1",
        issued_at=time.time(),
        granted_scopes=frozenset({"act"}),
        required_scope="act",
        assumed_state={},
    )
    base.update(overrides)
    req = Request(**base)
    return Request(**{**base, "signature": gate.sign(req)})


def test_state_store_backs_state_predicate():
    store = InMemoryStateStore({"locked": "false"})
    gate = Gate(SECRET, known_principals=PRINCIPALS, state_store=store)
    ok = signed(gate, assumed_state={"locked": "false"})
    assert gate.check(ok).verdict is Verdict.ALLOW

    store.set("locked", "true")
    drifted = signed(gate, nonce="n2", assumed_state={"locked": "false"})
    assert gate.check(drifted).verdict is Verdict.DENY


def test_nonce_store_shared_across_gate_instances():
    shared = InMemoryNonceStore()
    g1 = Gate(SECRET, known_principals=PRINCIPALS, nonce_store=shared)
    g2 = Gate(SECRET, known_principals=PRINCIPALS, nonce_store=shared)
    req = signed(g1, nonce="shared-nonce")
    assert g1.check(req).verdict is Verdict.ALLOW
    # Second gate sees the nonce as consumed via the shared store.
    assert g2.check(req).verdict is Verdict.DENY


def test_raising_state_store_fails_closed():
    class Boom:
        def read(self, key):
            raise RuntimeError("backend down")

    gate = Gate(SECRET, known_principals=PRINCIPALS, state_store=Boom())
    req = signed(gate, assumed_state={"k": "v"})
    receipt = gate.check(req)
    assert receipt.verdict is Verdict.DENY
    assert any(d.property == "state" and d.verdict is Verdict.DENY
               for d in receipt.decisions)


def test_cannot_pass_both_state_reader_and_state_store():
    with pytest.raises(ValueError):
        Gate(
            SECRET,
            known_principals=PRINCIPALS,
            state_reader=lambda k: "x",
            state_store=InMemoryStateStore(),
        )


def test_missing_state_key_denies_not_crashes():
    gate = Gate(SECRET, known_principals=PRINCIPALS, state_store=InMemoryStateStore())
    req = signed(gate, assumed_state={"absent": "expected"})
    receipt = gate.check(req)
    assert receipt.verdict is Verdict.DENY
