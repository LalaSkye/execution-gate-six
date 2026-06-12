"""Tamper-detection tests.

Mutating any committed trace must cause verification to fail. Each test
demonstrates one class of tamper. The verifier never silently repairs.
"""

import json
from pathlib import Path

import pytest

from execution_gate_six import (
    load_scenario,
    run_scenario,
    serialise_trace,
    verify,
)

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios" / "temporal"
SCENARIO_FILE = SCENARIOS / "fresh_then_stale.json"


def _write_records(path: Path, records: list[dict]) -> None:
    path.write_text(serialise_trace(records), encoding="utf-8")


def _fresh_records() -> list[dict]:
    return run_scenario(load_scenario(str(SCENARIO_FILE)))


def test_changing_a_verdict_breaks_verification(tmp_path):
    records = _fresh_records()
    records[1]["verdict"] = "ALLOW"  # flip the second-step denial
    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok
    assert result.first_failing_step == 1


def test_changing_a_failed_property_breaks_verification(tmp_path):
    records = _fresh_records()
    records[1]["failed_properties"] = ["Receipt"]  # was [Freshness]
    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok
    assert result.first_failing_step == 1


def test_changing_one_record_breaks_chain_from_there(tmp_path):
    records = _fresh_records()
    # Change a core field without recomputing record_hash. Chain breaks at i=0.
    records[0]["action"] = "redirect_funds"
    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok
    assert result.first_failing_step == 0


def test_removing_a_record_causes_verification_failure(tmp_path):
    records = _fresh_records()
    records.pop()  # drop the last step
    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok


def test_reordering_records_causes_verification_failure(tmp_path):
    records = _fresh_records()
    assert len(records) >= 2
    records[0], records[1] = records[1], records[0]
    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok
    # Reordering changes step numbers and chain order, so failure must come
    # at or before the first reordered position.
    assert result.first_failing_step is not None


def test_recomputing_hash_after_tamper_still_fails(tmp_path):
    """Even if an attacker rewrites the record_hash to match the tampered
    core, the previous_record_hash chain (and the re-derivation against the
    gate) still fails. We re-derive hashes locally to simulate the attack.
    """
    from execution_gate_six.temporal import GENESIS_HASH, _hash_record
    from execution_gate_six.trace_verify import _CORE_FIELDS

    records = _fresh_records()
    # Tamper with a verdict, then recompute hashes locally as an attacker would.
    records[1]["verdict"] = "ALLOW"
    prev = GENESIS_HASH
    for r in records:
        core = {k: r[k] for k in _CORE_FIELDS if k in r}
        r["previous_record_hash"] = prev
        r["record_hash"] = _hash_record(prev, core)
        prev = r["record_hash"]

    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    # Verification fails because the verifier re-runs the gate and the
    # gate's re-derived ALLOW/DENY pattern disagrees with the tampered trace.
    assert not result.ok
    assert result.first_failing_step is not None


def test_changing_a_reason_code_breaks_verification(tmp_path):
    records = _fresh_records()
    # Step 1 has at least one reason code (e.g. 'freshness_stale').
    assert records[1]["reason_codes"], "fixture must produce at least one reason code"
    records[1]["reason_codes"] = ["counterfeit_code"]
    out = tmp_path / "trace.jsonl"
    _write_records(out, records)
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok
    assert result.first_failing_step == 1


def test_malformed_jsonl_line_is_rejected(tmp_path):
    records = _fresh_records()
    body = serialise_trace(records).rstrip("\n") + "\n{not-json}\n"
    out = tmp_path / "trace.jsonl"
    out.write_text(body, encoding="utf-8")
    result = verify(str(SCENARIO_FILE), str(out))
    assert not result.ok
    assert "trace load failed" in result.reason
