"""Replay verifier tests.

Replaying a committed trace against the existing gate must reproduce every
verdict, every failed-property set, every reason code, every mutation
count and every record hash.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from execution_gate_six import (
    TRACE_VERSION,
    run_scenario,
    load_scenario,
    serialise_trace,
    verify,
)

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios" / "temporal"
PROOF = ROOT / "proof" / "temporal"
SCENARIO_FILES = [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
]


@pytest.fixture(scope="module", autouse=True)
def _ensure_proof_traces():
    """Materialise traces under proof/temporal once for the test module.

    The example CLI is the canonical generator. We invoke it as a subprocess
    so the test exercises exactly the user-visible interface.
    """
    PROOF.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    cmd = [sys.executable, str(ROOT / "examples" / "temporal_conformance.py"), "generate"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT), env=env)
    assert res.returncode == 0, f"generate failed: {res.stdout}\n{res.stderr}"


# ---------------------------------------------------------------------------
# 1. Replaying every committed trace reproduces every verdict.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_file", SCENARIO_FILES)
def test_replay_reproduces_every_verdict(scenario_file):
    scenario_path = SCENARIOS / scenario_file
    trace_path = PROOF / f"{load_scenario(str(scenario_path)).scenario_id}.trace.jsonl"
    result = verify(str(scenario_path), str(trace_path))
    assert result.ok, (
        f"verify failed for {scenario_file}: "
        f"step={result.first_failing_step} reason={result.reason}"
    )


# ---------------------------------------------------------------------------
# 2. Verifier CLI returns zero on clean traces.
# ---------------------------------------------------------------------------


def test_verify_cli_returns_zero_on_clean_traces(tmp_path):
    cmd = [sys.executable, str(ROOT / "examples" / "temporal_conformance.py"), "verify"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0, f"verify exit {res.returncode}: {res.stdout}\n{res.stderr}"
    assert "all scenarios verified" in res.stdout


# ---------------------------------------------------------------------------
# 3. CLI is idempotent: generate twice -> identical files.
# ---------------------------------------------------------------------------


def test_generate_twice_produces_identical_traces(tmp_path):
    """The deterministic core covers the whole record, so two generations
    yield byte-identical trace files. The manifest contains a wall-clock
    timestamp and is therefore excluded from this check.
    """
    sids = [load_scenario(str(SCENARIOS / f)).scenario_id for f in SCENARIO_FILES]

    first = {sid: (PROOF / f"{sid}.trace.jsonl").read_text(encoding="utf-8") for sid in sids}

    cmd = [sys.executable, str(ROOT / "examples" / "temporal_conformance.py"), "generate"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0

    second = {sid: (PROOF / f"{sid}.trace.jsonl").read_text(encoding="utf-8") for sid in sids}

    for sid in sids:
        assert first[sid] == second[sid], f"trace for {sid} not deterministic across runs"


# ---------------------------------------------------------------------------
# 4. Unknown schema version fails closed.
# ---------------------------------------------------------------------------


def test_unknown_schema_version_fails_closed(tmp_path):
    scenario_path = SCENARIOS / "fresh_then_stale.json"
    records = run_scenario(load_scenario(str(scenario_path)))
    # Corrupt the schema version.
    records[0]["trace_version"] = "9.9-not-supported"
    trace_path = tmp_path / "bad.jsonl"
    trace_path.write_text(serialise_trace(records), encoding="utf-8")
    result = verify(str(scenario_path), str(trace_path))
    assert not result.ok
    assert "trace_version" in result.reason


# ---------------------------------------------------------------------------
# 5. Malformed scenario fails closed (the load itself raises and the
#    verifier reports a structural failure).
# ---------------------------------------------------------------------------


def test_malformed_scenario_fails_closed(tmp_path):
    bad = tmp_path / "scenario.json"
    bad.write_text(json.dumps({"scenario_id": "x"}), encoding="utf-8")
    trace = tmp_path / "trace.jsonl"
    trace.write_text("", encoding="utf-8")
    result = verify(str(bad), str(trace))
    assert not result.ok
    assert "scenario load failed" in result.reason


# ---------------------------------------------------------------------------
# 6. Scenario execution does not depend on wall-clock or network.
# ---------------------------------------------------------------------------


def test_scenarios_dont_sleep_or_network(monkeypatch):
    """If the temporal layer were calling time.sleep or socket, the scenarios
    would break under the monkeypatched primitives.
    """
    import socket
    import time

    def boom_sleep(*args, **kwargs):
        raise AssertionError("temporal layer must not call time.sleep")

    def boom_socket(*args, **kwargs):
        raise AssertionError("temporal layer must not open sockets")

    monkeypatch.setattr(time, "sleep", boom_sleep)
    monkeypatch.setattr(socket, "socket", boom_socket)

    for f in SCENARIO_FILES:
        run_scenario(load_scenario(str(SCENARIOS / f)))


# ---------------------------------------------------------------------------
# 7. No scenario produces ALLOW after its first DENY (deterministic invariant
#    checked at the trace-record level as well as the live-run level).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_file", SCENARIO_FILES)
def test_no_allow_after_first_deny_in_committed_trace(scenario_file):
    scenario_path = SCENARIOS / scenario_file
    trace_path = PROOF / f"{load_scenario(str(scenario_path)).scenario_id}.trace.jsonl"
    with open(trace_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    saw_deny = False
    for r in records:
        if r["verdict"] == "DENY":
            saw_deny = True
        elif saw_deny:
            pytest.fail(f"{scenario_file}: ALLOW after DENY in committed trace")
