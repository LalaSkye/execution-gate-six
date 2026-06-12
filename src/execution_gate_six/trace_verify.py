"""Replay verifier for temporal conformance traces.

This is a trace-independent replay verifier that runs against the same
gate implementation. It does NOT constitute an independently implemented
verification engine: it reuses ``execution_gate_six.gate.Gate`` and the
temporal runner. Its independence is limited to the recorded trace --
the recorded verdicts are not treated as authoritative; verdicts are
re-derived from the scenario by re-running the gate.

The verifier:
    1. Loads one trace (JSONL).
    2. Loads the corresponding scenario.
    3. Re-runs the scenario through the same gate implementation.
    4. Compares verdict, failed properties, reason codes, mutation counts
       and hash-chain continuity, in order.
    5. Returns the first failing step (if any).

Fail-closed:
    - Unknown trace_version -> mismatch.
    - Re-derived record_hash that differs from the trace -> mismatch.
    - Mismatched length -> mismatch.
    - Malformed scenario -> mismatch (the runner raises during load).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .temporal import (
    TRACE_VERSION,
    TemporalScenario,
    GENESIS_HASH,
    _canonical_json,
    _hash_record,
    run_scenario,
)


# Fields that compose the deterministic record core. Operational metadata
# (previous_record_hash, record_hash) is verified by chain-rehashing, not by
# field-equality, so it does not appear here.
_CORE_FIELDS = (
    "trace_version",
    "scenario_id",
    "step",
    "event",
    "request_id",
    "principal",
    "action",
    "verdict",
    "failed_properties",
    "reason_codes",
    "mutation_count_before",
    "mutation_count_after",
)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    first_failing_step: int | None
    reason: str
    rederived_records: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "first_failing_step": self.first_failing_step,
            "reason": self.reason,
            "checked_records": len(self.rederived_records),
        }


def load_scenario(path: str) -> TemporalScenario:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return TemporalScenario.from_dict(raw)


def load_trace(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"trace line {line_no} is not valid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"trace line {line_no} must be a JSON object")
            records.append(obj)
    return records


def verify(scenario_path: str, trace_path: str) -> VerifyResult:
    """Verify a trace against a scenario by re-running and comparing.

    Returns a :class:`VerifyResult`. The caller decides what to do with a
    failed result; the verifier itself never raises for ordinary mismatch.
    """
    try:
        scenario = load_scenario(scenario_path)
    except Exception as exc:
        return VerifyResult(False, None, f"scenario load failed: {exc}", [])

    try:
        recorded = load_trace(trace_path)
    except Exception as exc:
        return VerifyResult(False, None, f"trace load failed: {exc}", [])

    # Schema version gate.
    for r in recorded:
        if r.get("trace_version") != TRACE_VERSION:
            return VerifyResult(
                False, r.get("step"),
                f"unsupported trace_version: {r.get('trace_version')!r}",
                [],
            )

    rederived = run_scenario(scenario)

    if len(recorded) != len(rederived):
        return VerifyResult(
            False, None,
            f"record count mismatch: trace has {len(recorded)}, "
            f"re-derived {len(rederived)}",
            rederived,
        )

    prev_hash = GENESIS_HASH
    for i, (r, d) in enumerate(zip(recorded, rederived)):
        # 1. Core-field equality.
        for field in _CORE_FIELDS:
            if r.get(field) != d.get(field):
                return VerifyResult(
                    False, i,
                    f"field {field!r} mismatch at step {i}: "
                    f"trace={r.get(field)!r} expected={d.get(field)!r}",
                    rederived,
                )
        # 2. Previous-hash continuity.
        if r.get("previous_record_hash") != prev_hash:
            return VerifyResult(
                False, i,
                f"previous_record_hash mismatch at step {i}: "
                f"trace={r.get('previous_record_hash')!r} expected={prev_hash!r}",
                rederived,
            )
        # 3. Record-hash recomputation.
        core = {k: r[k] for k in _CORE_FIELDS if k in r}
        expected_hash = _hash_record(prev_hash, core)
        if r.get("record_hash") != expected_hash:
            return VerifyResult(
                False, i,
                f"record_hash mismatch at step {i}: "
                f"trace={r.get('record_hash')!r} expected={expected_hash!r}",
                rederived,
            )
        prev_hash = r["record_hash"]

    return VerifyResult(True, None, "ok", rederived)
