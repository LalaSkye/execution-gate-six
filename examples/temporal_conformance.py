"""Temporal conformance proof pack: generate + verify.

Run:
    python examples/temporal_conformance.py generate
    python examples/temporal_conformance.py verify

The pack is a bounded test layer over the existing six-property gate. It
applies an ordered sequence of changes to a fixed scenario and records what
the existing gate decides at each step. It does NOT introduce a second
authority model; the gate's Authority, Scope, Freshness, Replay, State and
Receipt predicates remain canonical.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path

# Make the in-tree src/ importable when running this example directly.
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from execution_gate_six import (  # noqa: E402
    TRACE_VERSION,
    load_scenario,
    run_scenario,
    serialise_trace,
    verify,
)


SCENARIOS_DIR = ROOT / "scenarios" / "temporal"
PROOF_DIR = ROOT / "proof" / "temporal"
SCENARIO_FILES = [
    "fresh_then_stale.json",
    "authority_removed.json",
    "scope_narrowed.json",
    "state_drift.json",
    "replay_after_allow.json",
]


def _trace_path(scenario_name: str) -> Path:
    return PROOF_DIR / f"{scenario_name}.trace.jsonl"


def _scenario_path(name: str) -> Path:
    return SCENARIOS_DIR / name


def _trace_root(records: list[dict]) -> str:
    if not records:
        return "sha256:" + hashlib.sha256(b"empty").hexdigest()
    return records[-1]["record_hash"]


def cmd_generate(args: argparse.Namespace) -> int:
    PROOF_DIR.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "pack_version": TRACE_VERSION,
        "execution_gate_six_version": _read_version(),
        "scenarios": [],
        "verifier_command": "python examples/temporal_conformance.py verify",
        "generated_at_iso8601": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "claim": (
            "On the included deterministic scenarios, the pack identifies and "
            "replays the first step at which an initially admissible request "
            "becomes inadmissible under the existing Authority, Scope, "
            "Freshness, Replay or State checks."
        ),
        "claim_boundary": "See CLAIM_BOUNDARY.md and the temporal README.",
    }

    for name in SCENARIO_FILES:
        scenario = load_scenario(str(_scenario_path(name)))
        records = run_scenario(scenario)
        out = _trace_path(scenario.scenario_id)
        out.write_text(serialise_trace(records), encoding="utf-8")
        manifest["scenarios"].append({
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "scenario_file": str(_scenario_path(name).relative_to(ROOT)),
            "trace_file": str(out.relative_to(ROOT)),
            "step_count": len(records),
            "trace_root": _trace_root(records),
            "expected_first_denied_step": _first_denied_step(scenario),
        })
        print(f"[generate] {scenario.scenario_id}: {len(records)} steps -> {out.relative_to(ROOT)}")

    manifest_path = PROOF_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[generate] manifest -> {manifest_path.relative_to(ROOT)}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    failures = 0
    for name in SCENARIO_FILES:
        scenario_path = _scenario_path(name)
        scenario = load_scenario(str(scenario_path))
        trace_path = _trace_path(scenario.scenario_id)
        if not trace_path.exists():
            print(f"[verify] {scenario.scenario_id}: MISSING trace at {trace_path.relative_to(ROOT)}")
            failures += 1
            continue
        result = verify(str(scenario_path), str(trace_path))
        if result.ok:
            print(f"[verify] {scenario.scenario_id}: OK ({len(result.rederived_records)} records)")
        else:
            print(
                f"[verify] {scenario.scenario_id}: FAIL "
                f"(step={result.first_failing_step}, reason={result.reason})"
            )
            failures += 1
    if failures:
        print(f"[verify] {failures} scenario(s) failed verification")
        return 1
    print("[verify] all scenarios verified")
    return 0


def _first_denied_step(scenario) -> int | None:
    for step in scenario.steps:
        if step.expected_verdict == "DENY":
            return step.step
    return None


def _read_version() -> str:
    try:
        from execution_gate_six import __version__
        return __version__
    except Exception:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate", help="Generate proof traces and manifest from scenarios")
    sub.add_parser("verify", help="Verify existing traces against the gate by replay")
    args = parser.parse_args(argv)
    if args.cmd == "generate":
        return cmd_generate(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    parser.error(f"unknown subcommand: {args.cmd}")
    return 2  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
