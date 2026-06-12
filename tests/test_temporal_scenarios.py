"""Scenario-verdict tests.

Each test runs one scenario through the temporal runner and asserts:
    - the per-step expected verdict;
    - the expected failed property appears in the trace when DENY;
    - the mutation-count discipline (ALLOW may increment, DENY must not);
    - the trace is internally hash-chained.
"""

import json
from pathlib import Path

import pytest

from execution_gate_six import (
    TRACE_VERSION,
    Verdict,
    load_scenario,
    run_scenario,
)

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios" / "temporal"


def _load(name: str):
    return load_scenario(str(SCENARIOS / name))


def _records(name: str):
    return run_scenario(_load(name))


# ---------------------------------------------------------------------------
# Per-scenario verdict expectations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_file,expected_per_step",
    [
        (
            "fresh_then_stale.json",
            [
                ("ALLOW", None),
                ("DENY", "Freshness"),
            ],
        ),
        (
            "authority_removed.json",
            [
                ("ALLOW", None),
                ("DENY", "Authority"),     # remove + reissue with fresh nonce isolates to Authority
            ],
        ),
        (
            "scope_narrowed.json",
            [
                ("ALLOW", None),
                ("DENY", "Scope"),
            ],
        ),
        (
            "state_drift.json",
            [
                ("ALLOW", None),
                ("DENY", "State"),         # mutate_state + reissue with fresh nonce isolates to State
            ],
        ),
        (
            "replay_after_allow.json",
            [
                ("ALLOW", None),
                ("DENY", "Replay"),
            ],
        ),
    ],
)
def test_scenario_verdicts_match_expectation(scenario_file, expected_per_step):
    records = _records(scenario_file)
    assert len(records) == len(expected_per_step), (
        f"step count mismatch for {scenario_file}: {len(records)} vs {len(expected_per_step)}"
    )
    for i, ((exp_verdict, exp_prop), record) in enumerate(zip(expected_per_step, records)):
        assert record["verdict"] == exp_verdict, (
            f"{scenario_file} step {i}: expected verdict {exp_verdict}, got {record['verdict']} "
            f"(failed_properties={record['failed_properties']})"
        )
        if exp_prop is not None:
            # The gate may name several independent failures (e.g. Freshness +
            # Replay if the nonce was consumed). The expected property must
            # appear; the trace is permitted to record additional independent
            # failures faithfully.
            assert exp_prop in record["failed_properties"], (
                f"{scenario_file} step {i}: expected {exp_prop} in failed_properties, "
                f"got {record['failed_properties']}"
            )


# ---------------------------------------------------------------------------
# Mutation discipline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_file", [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
])
def test_deny_steps_do_not_mutate(scenario_file):
    """Every DENY step leaves mutation_count_after == mutation_count_before."""
    for record in _records(scenario_file):
        if record["verdict"] == "DENY":
            assert record["mutation_count_after"] == record["mutation_count_before"], (
                f"{scenario_file} step {record['step']}: DENY changed mutation count "
                f"{record['mutation_count_before']} -> {record['mutation_count_after']}"
            )


def test_replay_after_allow_total_mutation_is_one():
    """After one ALLOW and one replayed DENY, total mutation count is one."""
    records = _records("replay_after_allow.json")
    assert records[0]["verdict"] == "ALLOW"
    assert records[0]["mutation_count_after"] == 1
    assert records[1]["verdict"] == "DENY"
    assert records[1]["mutation_count_after"] == 1  # unchanged from previous step


# ---------------------------------------------------------------------------
# Internal chain continuity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_file", [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
])
def test_trace_chain_is_internally_continuous(scenario_file):
    records = _records(scenario_file)
    for i in range(1, len(records)):
        assert records[i]["previous_record_hash"] == records[i - 1]["record_hash"], (
            f"{scenario_file} step {i}: chain break"
        )


@pytest.mark.parametrize("scenario_file", [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
])
def test_trace_version_is_stable(scenario_file):
    for record in _records(scenario_file):
        assert record["trace_version"] == TRACE_VERSION


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_file", [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
])
def test_run_twice_produces_equivalent_deterministic_cores(scenario_file):
    """Generating the same scenario twice yields the same deterministic trace.

    The deterministic core covers everything except operational metadata.
    For this pack, operational metadata is intentionally not embedded in
    records; the entire record (including hashes) is therefore deterministic.
    """
    first = _records(scenario_file)
    second = _records(scenario_file)
    assert first == second


# ---------------------------------------------------------------------------
# No-effect-after-transition invariant
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Isolation regression: the invalidating step names exactly one property.
# Every scenario except replay_after_allow MUST isolate the named property
# at its invalidating step (no spurious Replay, no spurious Freshness, no
# spurious State). replay_after_allow is excluded because its invalidating
# property IS Replay.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_file,deny_step_index,expected_only_property",
    [
        ("fresh_then_stale.json", 1, "Freshness"),
        ("authority_removed.json", 1, "Authority"),
        ("scope_narrowed.json", 1, "Scope"),
        ("state_drift.json", 1, "State"),
    ],
)
def test_invalidating_step_isolates_to_one_property(
    scenario_file, deny_step_index, expected_only_property
):
    record = _records(scenario_file)[deny_step_index]
    assert record["verdict"] == "DENY"
    assert record["failed_properties"] == [expected_only_property], (
        f"{scenario_file} step {deny_step_index}: expected ONLY "
        f"[{expected_only_property!r}], got {record['failed_properties']!r}"
    )


def test_fresh_then_stale_does_not_trip_replay():
    """Explicit regression: the freshness invalidation must NOT name Replay."""
    record = _records("fresh_then_stale.json")[1]
    assert "Replay" not in record["failed_properties"], (
        f"Freshness scenario unexpectedly tripped Replay: {record['failed_properties']!r}"
    )
    assert "Freshness" in record["failed_properties"]


def test_fresh_then_stale_total_mutation_is_one():
    """Only the ALLOW step may mutate. The denied freshness step must not."""
    records = _records("fresh_then_stale.json")
    assert records[0]["verdict"] == "ALLOW"
    assert records[0]["mutation_count_after"] == 1
    assert records[1]["verdict"] == "DENY"
    assert records[1]["mutation_count_after"] == 1  # unchanged
    assert records[1]["mutation_count_before"] == 1


@pytest.mark.parametrize("scenario_file", [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
])
def test_no_allow_after_invalidating_transition(scenario_file):
    """After the first DENY in the trace, no later step is ALLOW unless the
    fixture explicitly issued a NEW valid request. Our five fixtures contain
    no such re-issue, so this is a strict 'no ALLOW after first DENY' check.
    """
    records = _records(scenario_file)
    saw_deny = False
    for record in records:
        if record["verdict"] == "DENY":
            saw_deny = True
        elif saw_deny:
            pytest.fail(
                f"{scenario_file} step {record['step']}: ALLOW after a prior DENY "
                f"and no scenario in this pack issues a new valid request after a DENY"
            )
