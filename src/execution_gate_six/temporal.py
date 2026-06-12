"""Temporal conformance: ordered scenario runner over the existing six-property gate.

This module is a thin layer on top of :class:`execution_gate_six.gate.Gate`.
It does NOT introduce a second authority model. It applies an ordered
sequence of changes to a fixed scenario and records what the existing gate
decides at each step.

Narrow question answered:

    Given a fixed sequence of changes, at which step does an initially
    admissible request become inadmissible, which existing gate property
    caused the transition, and can a replay verifier using the same gate
    implementation re-derive every verdict?

Operational invariant:

    valid request at step n
      + explicit invalidating transition at step n+1
      = fail-closed verdict at step n+1
      + replayable trace
      + zero downstream mutation after refusal

Determinism rules:
    - No wall-clock dependence. Scenarios use a simulated clock advanced by
      the ``advance_time`` event.
    - No randomness. Fixture-supplied IDs only.
    - All mutation goes through a ``MutationProbe`` whose count is recorded
      before and after every step.
    - Trace records are hash-chained (sha256 over canonical JSON of the
      previous-record hash plus the current record core).

The temporal layer never weakens the gate. A denied step does not commit a
nonce; an allowed step does. That behaviour is inherited from
``Gate.check`` and is what the trace records.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .adapters import InMemoryNonceStore, InMemoryStateStore
from .gate import Decision, Gate, PROPERTIES, Request, Verdict


TRACE_VERSION = "0.1"

# Map gate-internal lowercase property names to the canonical capitalised
# names used in scenario fixtures (Authority, Scope, Freshness, Replay,
# State, Receipt). The capitalisation is fixture-facing only; gate output
# remains canonical lowercase.
_FIXTURE_NAME = {
    "authority": "Authority",
    "scope": "Scope",
    "freshness": "Freshness",
    "replay": "Replay",
    "state": "State",
    "receipt": "Receipt",
}


# ---------------------------------------------------------------------------
# Mutation probe — the tiny side effect that ALLOW is permitted to perform
# and DENY is not. Intentionally not a real system action.
# ---------------------------------------------------------------------------


class MutationProbe:
    """A harmless in-memory mutation surface.

    The probe counts increments and records labels. ``apply`` is only ever
    invoked from inside the temporal runner when the existing gate returns
    ALLOW for a scenario step. DENY paths never reach ``apply``.

    The probe deliberately does not simulate financial, medical or
    production operations. It exists to make the consequence-or-no
    distinction visible in the trace.
    """

    def __init__(self) -> None:
        self._count: int = 0
        self._labels: list[str] = []

    @property
    def count(self) -> int:
        return self._count

    def apply(self, label: str) -> None:
        self._count += 1
        self._labels.append(label)


# ---------------------------------------------------------------------------
# Deterministic clock
# ---------------------------------------------------------------------------


class _SimClock:
    """Deterministic clock the temporal runner uses.

    Time only advances when a scenario step says ``advance_time``. Tests do
    not sleep. A 30-second expiry is reached immediately.
    """

    def __init__(self, start: float) -> None:
        self._now: float = float(start)

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("simulated clock cannot run backwards")
        self._now += float(seconds)


# ---------------------------------------------------------------------------
# Scenario dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TemporalStep:
    """One ordered step in a scenario."""

    step: int
    event: str
    payload: dict[str, Any] = field(default_factory=dict)
    expected_verdict: str | None = None
    expected_failed_property: str | None = None
    label: str = ""


@dataclass(frozen=True)
class TemporalScenario:
    scenario_id: str
    description: str
    secret: str
    known_principals: tuple[str, ...]
    max_age_seconds: float
    initial_state: dict[str, str]
    request: dict[str, Any]
    steps: tuple[TemporalStep, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "TemporalScenario":
        # Fail-closed parsing: any structural defect raises and is caught by
        # the runner / verifier, which then treats the load as a denied step.
        if not isinstance(raw, dict):
            raise ValueError("scenario must be a JSON object")
        required = {"scenario_id", "description", "secret", "known_principals",
                    "max_age_seconds", "initial_state", "request", "steps"}
        missing = required - set(raw)
        if missing:
            raise ValueError(f"scenario missing fields: {sorted(missing)}")
        steps_raw = raw["steps"]
        if not isinstance(steps_raw, list) or not steps_raw:
            raise ValueError("scenario.steps must be a non-empty list")
        steps: list[TemporalStep] = []
        for i, s in enumerate(steps_raw):
            if not isinstance(s, dict):
                raise ValueError(f"step {i} must be an object")
            if "step" not in s or "event" not in s:
                raise ValueError(f"step {i} requires 'step' and 'event'")
            steps.append(TemporalStep(
                step=int(s["step"]),
                event=str(s["event"]),
                payload={k: v for k, v in s.items()
                         if k not in {"step", "event", "expected_verdict",
                                       "expected_failed_property", "label"}},
                expected_verdict=s.get("expected_verdict"),
                expected_failed_property=s.get("expected_failed_property"),
                label=s.get("label", ""),
            ))
        # Steps must be contiguous starting at 0 and monotonically ordered.
        for i, s in enumerate(steps):
            if s.step != i:
                raise ValueError(f"steps must be 0..N contiguous; got {s.step} at index {i}")
        known = tuple(raw["known_principals"])
        if not all(isinstance(p, str) for p in known):
            raise ValueError("known_principals must be a list of strings")
        return cls(
            scenario_id=str(raw["scenario_id"]),
            description=str(raw["description"]),
            secret=str(raw["secret"]),
            known_principals=known,
            max_age_seconds=float(raw["max_age_seconds"]),
            initial_state=dict(raw["initial_state"]),
            request=dict(raw["request"]),
            steps=tuple(steps),
        )


# ---------------------------------------------------------------------------
# Runtime context: the world the runner manipulates between steps
# ---------------------------------------------------------------------------


@dataclass
class _RunContext:
    scenario: TemporalScenario
    clock: _SimClock
    state_store: InMemoryStateStore
    nonce_store: InMemoryNonceStore
    known_principals: set[str]
    gate: Gate
    request_template: dict[str, Any]
    current_request: Request | None
    probe: MutationProbe


def _build_request(
    gate: Gate,
    template: dict[str, Any],
    overrides: dict[str, Any] | None = None,
) -> Request:
    """Build a freshly-signed request from a JSON-style template + overrides."""
    base = {
        "action": template["action"],
        "principal": template["principal"],
        "nonce": template["nonce"],
        "issued_at": float(template["issued_at"]),
        "granted_scopes": frozenset(template.get("granted_scopes", [])),
        "required_scope": template.get("required_scope", ""),
        "assumed_state": dict(template.get("assumed_state", {})),
    }
    if overrides:
        if "granted_scopes" in overrides:
            base["granted_scopes"] = frozenset(overrides["granted_scopes"])
        if "assumed_state" in overrides:
            base["assumed_state"] = dict(overrides["assumed_state"])
        for k in ("action", "principal", "nonce", "issued_at", "required_scope"):
            if k in overrides:
                base[k] = overrides[k]
    unsigned = Request(**base)
    sig = gate.sign(unsigned)
    return Request(**{**base, "signature": sig})


def _build_context(scenario: TemporalScenario) -> _RunContext:
    clock = _SimClock(start=float(scenario.request.get("issued_at", 1_000_000.0)))
    state_store = InMemoryStateStore(dict(scenario.initial_state))
    nonce_store = InMemoryNonceStore()
    known = set(scenario.known_principals)
    gate = Gate(
        scenario.secret.encode(),
        known_principals=frozenset(known),
        max_age_seconds=scenario.max_age_seconds,
        state_store=state_store,
        nonce_store=nonce_store,
        clock=clock,
    )
    # Adapter for membership mutation: the gate snapshots known_principals
    # at construction, so 'remove_authority' must rebuild the gate. We hold
    # the mutable set and rebuild on demand via _rebuild_gate.
    ctx = _RunContext(
        scenario=scenario,
        clock=clock,
        state_store=state_store,
        nonce_store=nonce_store,
        known_principals=known,
        gate=gate,
        request_template=dict(scenario.request),
        current_request=None,
        probe=MutationProbe(),
    )
    return ctx


def _rebuild_gate(ctx: _RunContext) -> None:
    """Rebuild the gate after a recognised-principals change.

    The existing Gate freezes its known_principals at construction. To model
    the 'authority removed' transition without altering core semantics we
    construct a new Gate with the updated set, while keeping the same
    state_store, nonce_store, secret and clock. Replay protection is
    therefore preserved across the rebuild.
    """
    ctx.gate = Gate(
        ctx.scenario.secret.encode(),
        known_principals=frozenset(ctx.known_principals),
        max_age_seconds=ctx.scenario.max_age_seconds,
        state_store=ctx.state_store,
        nonce_store=ctx.nonce_store,
        clock=ctx.clock,
    )


# ---------------------------------------------------------------------------
# Trace records
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hash_record(prev_hash: str, core: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(b"|")
    h.update(_canonical_json(core).encode())
    return "sha256:" + h.hexdigest()


def _record_core(
    scenario_id: str,
    step: int,
    event: str,
    request_id: str,
    principal: str,
    action: str,
    verdict: str,
    failed_properties: list[str],
    reason_codes: list[str],
    mutation_count_before: int,
    mutation_count_after: int,
) -> dict[str, Any]:
    """The deterministic core of one trace record.

    Operational metadata (decided_at, digest) is captured separately so
    timestamps do not affect deterministic verdict replay.
    """
    return {
        "trace_version": TRACE_VERSION,
        "scenario_id": scenario_id,
        "step": step,
        "event": event,
        "request_id": request_id,
        "principal": principal,
        "action": action,
        "verdict": verdict,
        "failed_properties": failed_properties,
        "reason_codes": reason_codes,
        "mutation_count_before": mutation_count_before,
        "mutation_count_after": mutation_count_after,
    }


def _failed_properties(decisions: Iterable[Decision]) -> list[str]:
    return [_FIXTURE_NAME[d.property] for d in decisions if d.verdict is Verdict.DENY]


def _reason_codes(decisions: Iterable[Decision]) -> list[str]:
    """Stable short codes for a denied decision.

    Reason codes are derived from the property and a coarse classification of
    the gate's free-text reason. Free text is intentionally NOT included in
    the deterministic trace core because it could vary across formatting.
    """
    codes: list[str] = []
    for d in decisions:
        if d.verdict is not Verdict.DENY:
            continue
        prop = d.property
        reason = d.reason.lower()
        if prop == "authority":
            codes.append("authority_unrecognised")
        elif prop == "scope":
            if "no required scope declared" in reason:
                codes.append("scope_undeclared")
            else:
                codes.append("scope_insufficient")
        elif prop == "freshness":
            if "future" in reason:
                codes.append("freshness_future")
            else:
                codes.append("freshness_stale")
        elif prop == "replay":
            codes.append("replay_nonce_seen")
        elif prop == "state":
            if "no reader configured" in reason:
                codes.append("state_no_reader")
            elif "predicate error" in reason:
                codes.append("state_predicate_error")
            else:
                codes.append("state_drift")
        elif prop == "receipt":
            if "no signature" in reason:
                codes.append("receipt_missing_signature")
            else:
                codes.append("receipt_signature_mismatch")
        else:
            codes.append(f"{prop}_denied")
    return codes


# ---------------------------------------------------------------------------
# Step events
# ---------------------------------------------------------------------------


def _execute_check_step(ctx: _RunContext, step: TemporalStep) -> tuple[Verdict, list[Decision]]:
    """Run the existing gate on the current request and apply the mutation
    probe if (and only if) the gate returns ALLOW.

    Returns the resulting verdict and decisions.
    """
    if ctx.current_request is None:
        # No request to check -> fail closed.
        # Synthesize a denied decision set to keep trace shape stable.
        synthetic = [Decision(p, Verdict.DENY, "no current request") for p in PROPERTIES]
        return Verdict.DENY, synthetic
    receipt = ctx.gate.check(ctx.current_request)
    if receipt.verdict is Verdict.ALLOW:
        ctx.probe.apply(step.label or step.event)
    return receipt.verdict, list(receipt.decisions)


def _apply_event(ctx: _RunContext, step: TemporalStep) -> tuple[Verdict, list[Decision]]:
    """Apply a single scenario event and return the gate verdict+decisions
    that the trace records for this step.

    Events that mutate the world (advance_time, mutate_state, remove_authority,
    narrow_scope) re-evaluate the *current* request after the change.
    The ``issue_request`` event installs a new signed request and evaluates it.
    The ``check`` event re-evaluates the current request without changes.
    The ``submit_request`` event re-submits the same prior request (replay).
    """
    event = step.event
    payload = step.payload

    if event == "issue_request":
        overrides = payload.get("overrides", {})
        ctx.current_request = _build_request(ctx.gate, ctx.request_template, overrides)
        return _execute_check_step(ctx, step)

    if event == "check":
        return _execute_check_step(ctx, step)

    if event == "advance_time":
        ctx.clock.advance(float(payload.get("seconds", 0)))
        return _execute_check_step(ctx, step)

    if event == "mutate_state":
        for k, v in payload.get("set", {}).items():
            ctx.state_store.set(str(k), str(v))
        return _execute_check_step(ctx, step)

    if event == "remove_authority":
        for p in payload.get("principals", []):
            ctx.known_principals.discard(str(p))
        _rebuild_gate(ctx)
        return _execute_check_step(ctx, step)

    if event == "remove_authority_and_reissue":
        # Remove the named principals from the recognised set and then issue a
        # freshly signed request with a new nonce so the failure isolates to
        # Authority rather than Replay. Issuance time is reset to the current
        # simulated clock so Freshness is also not implicated.
        for p in payload.get("principals", []):
            ctx.known_principals.discard(str(p))
        _rebuild_gate(ctx)
        new_nonce = payload.get("new_nonce")
        if new_nonce is None:
            raise ValueError("remove_authority_and_reissue requires 'new_nonce'")
        overrides = dict(payload.get("overrides", {}))
        overrides["nonce"] = str(new_nonce)
        overrides.setdefault("issued_at", ctx.clock())
        ctx.current_request = _build_request(ctx.gate, ctx.request_template, overrides)
        return _execute_check_step(ctx, step)

    if event == "mutate_state_and_reissue":
        # Mutate live state and then issue a freshly signed request with a new
        # nonce so the failure isolates to State rather than Replay. Issuance
        # time is reset to the current simulated clock so Freshness is not
        # implicated.
        for k, v in payload.get("set", {}).items():
            ctx.state_store.set(str(k), str(v))
        new_nonce = payload.get("new_nonce")
        if new_nonce is None:
            raise ValueError("mutate_state_and_reissue requires 'new_nonce'")
        overrides = dict(payload.get("overrides", {}))
        overrides["nonce"] = str(new_nonce)
        overrides.setdefault("issued_at", ctx.clock())
        ctx.current_request = _build_request(ctx.gate, ctx.request_template, overrides)
        return _execute_check_step(ctx, step)

    if event == "advance_time_and_reissue":
        # Advance the simulated clock and then issue a NEW signed request
        # that reuses the ORIGINAL grant issuance time. The reissue carries
        # a fresh, unused nonce so the failure isolates to Freshness rather
        # than Replay. Principal, action, scope and assumed state are
        # preserved from the scenario template unless explicitly overridden.
        ctx.clock.advance(float(payload.get("seconds", 0)))
        overrides = dict(payload.get("overrides", {}))
        new_nonce = payload.get("new_nonce")
        if new_nonce is None:
            raise ValueError("advance_time_and_reissue requires 'new_nonce'")
        overrides["nonce"] = str(new_nonce)
        # Original issuance time is preserved (it is the property under test).
        overrides.setdefault("issued_at", ctx.request_template["issued_at"])
        ctx.current_request = _build_request(ctx.gate, ctx.request_template, overrides)
        return _execute_check_step(ctx, step)

    if event == "narrow_scope":
        # Issue a NEW signed request with a narrowed granted_scopes set.
        new_template = dict(ctx.request_template)
        # Default to a fresh nonce so the failure is isolated to scope, not
        # replay, unless the scenario explicitly overrides the nonce.
        overrides = dict(payload.get("overrides", {}))
        overrides.setdefault("nonce", payload.get("new_nonce", ctx.request_template["nonce"] + "-s"))
        overrides["granted_scopes"] = list(payload.get("granted_scopes", []))
        # Re-issue at the current simulated time so freshness is unaffected.
        overrides["issued_at"] = ctx.clock()
        ctx.current_request = _build_request(ctx.gate, new_template, overrides)
        return _execute_check_step(ctx, step)

    if event == "submit_request":
        # Re-submit the current request unchanged (e.g. replay test).
        return _execute_check_step(ctx, step)

    raise ValueError(f"unknown event: {event}")


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------


GENESIS_HASH = "sha256:" + hashlib.sha256(b"temporal-conformance-v0.1-genesis").hexdigest()


def run_scenario(scenario: TemporalScenario) -> list[dict[str, Any]]:
    """Run a scenario through the existing gate and return ordered trace records.

    Each record contains both the deterministic core and the previous-record
    hash plus the current record hash. The records are returned as plain
    dicts; serialisation is the caller's responsibility.
    """
    ctx = _build_context(scenario)
    records: list[dict[str, Any]] = []
    prev_hash = GENESIS_HASH

    for step in scenario.steps:
        before = ctx.probe.count
        verdict, decisions = _apply_event(ctx, step)
        after = ctx.probe.count

        # request_id is the action+principal+nonce of the current request, or
        # a sentinel if no request exists at the time of evaluation.
        if ctx.current_request is not None:
            req = ctx.current_request
            request_id = f"{req.action}|{req.principal}|{req.nonce}"
            principal = req.principal
            action = req.action
        else:
            request_id = "<none>"
            principal = "<none>"
            action = "<none>"

        core = _record_core(
            scenario_id=scenario.scenario_id,
            step=step.step,
            event=step.event,
            request_id=request_id,
            principal=principal,
            action=action,
            verdict=verdict.value,
            failed_properties=_failed_properties(decisions),
            reason_codes=_reason_codes(decisions),
            mutation_count_before=before,
            mutation_count_after=after,
        )
        record_hash = _hash_record(prev_hash, core)
        record = {
            **core,
            "previous_record_hash": prev_hash,
            "record_hash": record_hash,
        }
        records.append(record)
        prev_hash = record_hash

    return records


def serialise_trace(records: list[dict[str, Any]]) -> str:
    """Return JSONL serialisation of a trace; deterministic per record."""
    return "\n".join(_canonical_json(r) for r in records) + "\n"
