"""Conformance suite.

The point of each test: prove that the six properties are enforced
*independently*. A request that passes five properties and fails one
must be DENIED. That independence is what content-only enforcement misses.
"""

import time

import pytest

from execution_gate_six import Gate, Request, Verdict

SECRET = b"test-secret-key"
PRINCIPALS = frozenset({"agent-alpha"})


def make_gate(**kw):
    return Gate(SECRET, known_principals=PRINCIPALS, **kw)


def signed_request(gate, **overrides):
    base = dict(
        action="transfer_funds",
        principal="agent-alpha",
        nonce="nonce-1",
        issued_at=time.time(),
        granted_scopes=frozenset({"transfer_funds"}),
        required_scope="transfer_funds",
        assumed_state={},
    )
    base.update(overrides)
    req = Request(**base)
    sig = gate.sign(req)
    return Request(**{**base, "signature": sig})


def test_fully_valid_request_is_allowed():
    gate = make_gate()
    receipt = gate.check(signed_request(gate))
    assert receipt.verdict is Verdict.ALLOW


def test_unknown_principal_denied_even_if_everything_else_valid():
    gate = make_gate()
    # Sign as the unknown principal so the receipt check would otherwise pass.
    req = signed_request(gate, principal="agent-omega")
    receipt = gate.check(req)
    assert receipt.verdict is Verdict.DENY
    assert any(d.property == "authority" and d.verdict is Verdict.DENY
               for d in receipt.decisions)


def test_scope_not_granted_denied():
    gate = make_gate()
    req = signed_request(gate, granted_scopes=frozenset({"read_balance"}))
    receipt = gate.check(req)
    assert receipt.verdict is Verdict.DENY
    assert any(d.property == "scope" and d.verdict is Verdict.DENY
               for d in receipt.decisions)


def test_stale_request_denied_even_when_authority_and_scope_valid():
    gate = make_gate(max_age_seconds=5.0)
    req = signed_request(gate, issued_at=time.time() - 60)
    receipt = gate.check(req)
    assert receipt.verdict is Verdict.DENY
    assert any(d.property == "freshness" and d.verdict is Verdict.DENY
               for d in receipt.decisions)


def test_replayed_request_denied_on_second_use():
    gate = make_gate()
    req = signed_request(gate, nonce="nonce-replay")
    first = gate.check(req)
    assert first.verdict is Verdict.ALLOW
    # Identical, otherwise-valid request, replayed.
    second = gate.check(req)
    assert second.verdict is Verdict.DENY
    assert any(d.property == "replay" and d.verdict is Verdict.DENY
               for d in second.decisions)


def test_denied_request_does_not_burn_its_nonce():
    gate = make_gate()
    # First attempt fails on scope, so the nonce must remain usable.
    bad = signed_request(gate, nonce="nonce-x", granted_scopes=frozenset())
    assert gate.check(bad).verdict is Verdict.DENY
    good = signed_request(gate, nonce="nonce-x")
    assert gate.check(good).verdict is Verdict.ALLOW


def test_state_drift_denied():
    live = {"account_locked": "false"}
    gate = make_gate(state_reader=lambda k: live.get(k, "<missing>"))
    # Request assumes account is unlocked; live state agrees -> allow.
    ok = signed_request(gate, assumed_state={"account_locked": "false"})
    assert gate.check(ok).verdict is Verdict.ALLOW
    # State drifts after the grant; a fresh, in-scope, authorised request is
    # still denied because the world changed.
    live["account_locked"] = "true"
    drifted = signed_request(gate, nonce="nonce-2",
                             assumed_state={"account_locked": "false"})
    receipt = gate.check(drifted)
    assert receipt.verdict is Verdict.DENY
    assert any(d.property == "state" and d.verdict is Verdict.DENY
               for d in receipt.decisions)


def test_tampered_signature_denied():
    gate = make_gate()
    req = signed_request(gate)
    tampered = Request(
        action=req.action, principal=req.principal, nonce=req.nonce,
        issued_at=req.issued_at, granted_scopes=req.granted_scopes,
        required_scope=req.required_scope, assumed_state=req.assumed_state,
        signature="deadbeef",
    )
    receipt = gate.check(tampered)
    assert receipt.verdict is Verdict.DENY
    assert any(d.property == "receipt" and d.verdict is Verdict.DENY
               for d in receipt.decisions)


def test_missing_signature_denied():
    gate = make_gate()
    req = Request(
        action="x", principal="agent-alpha", nonce="n",
        issued_at=time.time(), granted_scopes=frozenset({"x"}),
        required_scope="x", assumed_state={}, signature="",
    )
    receipt = gate.check(req)
    assert receipt.verdict is Verdict.DENY


def test_construction_requires_secret_fail_closed():
    with pytest.raises(ValueError):
        Gate(b"", known_principals=PRINCIPALS)


def test_receipt_is_emitted_for_every_decision():
    gate = make_gate()
    receipt = gate.check(signed_request(gate))
    assert len(receipt.decisions) == 6
    assert receipt.digest
    assert {d.property for d in receipt.decisions} == {
        "authority", "scope", "freshness", "replay", "state", "receipt"
    }
