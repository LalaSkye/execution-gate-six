"""The six-property execution gate.

Design principle: FAIL-CLOSED. The gate answers a question the rest of the
runtime-verification stack does not ask — not "is this action safe?" but
"is the permission to perform it still valid at the instant of execution?"

Six independent predicates. Each must return PASS for the gate to ALLOW.
Unknown / unverifiable -> the predicate returns DENY, and the gate denies.

The predicates are deliberately independent: a request may have valid
*authority* and valid *scope* yet still be denied because it was *replayed*,
or because the *state* it assumes no longer holds. That independence is the
whole point — it is the seam that content-only enforcement misses.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Mapping

from .adapters import InMemoryNonceStore, NonceStore, StateStore


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


# The six properties, in canonical order (CARD 5).
PROPERTIES = ("authority", "scope", "freshness", "replay", "state", "receipt")


@dataclass(frozen=True)
class Request:
    """A request to bind a consequence.

    Fields are intentionally minimal; richer systems extend this.
    """

    action: str
    principal: str
    nonce: str
    issued_at: float                      # unix seconds when authority was granted
    granted_scopes: frozenset[str] = field(default_factory=frozenset)
    required_scope: str = ""
    assumed_state: Mapping[str, str] = field(default_factory=dict)
    signature: str = ""                   # HMAC over the canonical payload

    def canonical_payload(self) -> bytes:
        payload = {
            "action": self.action,
            "principal": self.principal,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "granted_scopes": sorted(self.granted_scopes),
            "required_scope": self.required_scope,
            "assumed_state": dict(sorted(self.assumed_state.items())),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


@dataclass(frozen=True)
class Decision:
    property: str
    verdict: Verdict
    reason: str


@dataclass(frozen=True)
class Receipt:
    """Tamper-evident record of why the gate decided what it decided."""

    request_action: str
    principal: str
    verdict: Verdict
    decisions: tuple[Decision, ...]
    decided_at: float
    digest: str

    def to_dict(self) -> dict:
        return {
            "request_action": self.request_action,
            "principal": self.principal,
            "verdict": self.verdict.value,
            "decisions": [
                {"property": d.property, "verdict": d.verdict.value, "reason": d.reason}
                for d in self.decisions
            ],
            "decided_at": self.decided_at,
            "digest": self.digest,
        }


class Gate:
    """A fail-closed gate over the six properties.

    Authority + receipt integrity are verified with an HMAC secret.
    Freshness uses a max-age window. Replay uses a seen-nonce set.
    State is checked against a caller-supplied live-state reader, so the
    gate decides on *current* state, not state captured at request time.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        known_principals: frozenset[str],
        max_age_seconds: float = 30.0,
        state_reader: Callable[[str], str] | None = None,
        state_store: StateStore | None = None,
        nonce_store: NonceStore | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not secret:
            # Fail-closed even at construction: no secret, no trust.
            raise ValueError("Gate requires a non-empty secret (fail-closed).")
        if state_reader is not None and state_store is not None:
            raise ValueError("Provide either state_reader or state_store, not both.")
        self._secret = secret
        self._known_principals = known_principals
        self._max_age = max_age_seconds
        # Normalise state access to a single callable. A StateStore takes
        # precedence; otherwise the legacy callable; otherwise None.
        if state_store is not None:
            self._state_reader: Callable[[str], str] | None = state_store.read
        else:
            self._state_reader = state_reader
        self._nonce_store: NonceStore = nonce_store or InMemoryNonceStore()
        self._clock = clock

    # --- the six predicates -------------------------------------------------

    def _check_authority(self, req: Request) -> Decision:
        if req.principal not in self._known_principals:
            return Decision("authority", Verdict.DENY, "principal not recognised")
        return Decision("authority", Verdict.ALLOW, "principal recognised")

    def _check_scope(self, req: Request) -> Decision:
        if not req.required_scope:
            return Decision("scope", Verdict.DENY, "no required scope declared")
        if req.required_scope not in req.granted_scopes:
            return Decision("scope", Verdict.DENY, "required scope not granted")
        return Decision("scope", Verdict.ALLOW, "scope satisfied")

    def _check_freshness(self, req: Request) -> Decision:
        age = self._clock() - req.issued_at
        if age < 0:
            return Decision("freshness", Verdict.DENY, "issued in the future")
        if age > self._max_age:
            return Decision("freshness", Verdict.DENY, f"stale ({age:.1f}s > {self._max_age}s)")
        return Decision("freshness", Verdict.ALLOW, f"fresh ({age:.1f}s)")

    def _check_replay(self, req: Request) -> Decision:
        if self._nonce_store.seen(req.nonce):
            return Decision("replay", Verdict.DENY, "nonce already used")
        return Decision("replay", Verdict.ALLOW, "nonce unseen")

    def _check_state(self, req: Request) -> Decision:
        if self._state_reader is None:
            if req.assumed_state:
                return Decision("state", Verdict.DENY, "state assumed but no reader configured")
            return Decision("state", Verdict.ALLOW, "no state dependency")
        for key, expected in req.assumed_state.items():
            actual = self._state_reader(key)
            if actual != expected:
                return Decision("state", Verdict.DENY,
                                f"state '{key}' drifted: assumed {expected!r}, live {actual!r}")
        return Decision("state", Verdict.ALLOW, "assumed state matches live state")

    def _check_receipt(self, req: Request) -> Decision:
        expected = hmac.new(self._secret, req.canonical_payload(), hashlib.sha256).hexdigest()
        if not req.signature:
            return Decision("receipt", Verdict.DENY, "no signature on request")
        if not hmac.compare_digest(expected, req.signature):
            return Decision("receipt", Verdict.DENY, "signature mismatch (tampered or wrong key)")
        return Decision("receipt", Verdict.ALLOW, "signature valid")

    # --- the gate -----------------------------------------------------------

    def sign(self, req: Request) -> str:
        """Helper for callers to produce a valid signature for a request."""
        return hmac.new(self._secret, req.canonical_payload(), hashlib.sha256).hexdigest()

    def check(self, req: Request) -> Receipt:
        checks = (
            self._check_authority,
            self._check_scope,
            self._check_freshness,
            self._check_replay,
            self._check_state,
            self._check_receipt,
        )
        decisions: list[Decision] = []
        for prop, fn in zip(PROPERTIES, checks):
            try:
                decisions.append(fn(req))
            except Exception as exc:  # fail-closed on any predicate error
                decisions.append(Decision(prop, Verdict.DENY, f"predicate error: {exc}"))

        verdict = (
            Verdict.ALLOW
            if all(d.verdict is Verdict.ALLOW for d in decisions)
            else Verdict.DENY
        )

        # Replay protection only commits once the request is otherwise admissible
        # AND actually allowed — a denied request does not burn its nonce.
        if verdict is Verdict.ALLOW:
            self._nonce_store.consume(req.nonce)

        decided_at = self._clock()
        digest = hmac.new(
            self._secret,
            json.dumps(
                {
                    "action": req.action,
                    "principal": req.principal,
                    "verdict": verdict.value,
                    "decisions": [(d.property, d.verdict.value) for d in decisions],
                    "decided_at": decided_at,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            hashlib.sha256,
        ).hexdigest()

        return Receipt(
            request_action=req.action,
            principal=req.principal,
            verdict=verdict,
            decisions=tuple(decisions),
            decided_at=decided_at,
            digest=digest,
        )
