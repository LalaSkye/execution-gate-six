# Claim boundary — execution-gate-six and the temporal conformance pack

This document records the bounded public claim attached to this repository
and to the v0.1 temporal conformance pack.

## What this repository is

A small, fail-closed reference primitive that gates a request against six
independent properties at the instant of execution:

> Authority. Scope. Freshness. Replay. State. Receipt.

The gate is a single Python module. Adapters for state and nonce storage
are pluggable. There is no service, no dashboard, no hosted backend.

## Temporal conformance pack

The pack adds a deterministic, ordered scenario runner over the existing
gate. It applies fixture-supplied transitions (advance simulated time
and reissue, remove a principal from the recognised set and reissue,
narrow granted scopes, mutate live state and reissue, resubmit a
request) and records what the existing gate decides at each step. It
does not introduce a second authority model.

## Bounded claim

On the five included deterministic scenarios, the temporal conformance
pack shows when an initially admissible request becomes inadmissible
under the existing Authority, Scope, Freshness, Replay or State checks.
Each transition produces a hash-linked trace. A replay verifier using
the same gate implementation re-derives the verdict sequence, and
denied steps do not invoke the test mutation callback.

| Scenario              | Invalidating step event              | Property the trace isolates |
|-----------------------|--------------------------------------|-----------------------------|
| fresh_then_stale      | advance_time_and_reissue             | Freshness                   |
| authority_removed     | remove_authority_and_reissue         | Authority                   |
| scope_narrowed        | narrow_scope                         | Scope                       |
| state_drift           | mutate_state_and_reissue             | State                       |
| replay_after_allow    | submit_request                       | Replay                      |

Every DENY step leaves the in-memory mutation probe unchanged. Every
replay attempt produces no additional mutation. Each evaluation step is
written as a JSONL record with a previous-record hash plus a record
hash; any single-field tamper (verdict, failed property, reason code),
record removal or record reorder breaks verification.

The gate's per-step verdict is the canonical truth. Predicates are
independent, so the gate could in principle name multiple failed
properties at one step. The five scenarios above are constructed —
using the temporal-layer reissue events — so the invalidating step
isolates exactly one property. The regression test
`test_invalidating_step_isolates_to_one_property` enforces this; the
test `test_fresh_then_stale_does_not_trip_replay` further pins the
isolation for the freshness scenario specifically.

## Verifier scope and independence

The replay verifier in `execution_gate_six.trace_verify` is
*trace-independent*: it disregards the recorded verdict as authority and
re-derives every verdict by re-running the scenario through the same
gate implementation. It is **not** an independently implemented
verification engine; it reuses `execution_gate_six.gate.Gate` and the
temporal runner.

The verifier validly claims that it:

- disregards the recorded verdict as authority;
- reruns the scenario;
- re-derives the gate decisions;
- compares deterministic fields (verdict, failed properties, reason
  codes, mutation counts);
- verifies chain continuity (previous-record hash + record hash);
- rejects altered evidence and unsupported schema versions.

The verifier does not claim cross-implementation soundness, independent
implementation, or coverage of any path beyond what the scenarios
exercise.

## Non-claims

This work does not claim:

- certification or accreditation;
- production deployment or enterprise readiness;
- compliance with any specific regulation;
- complete authorisation, including identity management, key management,
  delegation graphs, multi-tenant isolation or audit-log archival;
- complete IAM;
- continuous enterprise monitoring;
- universal authority-decay coverage. The five scenarios are
  representative, not exhaustive;
- proof that every effect-capable execution path has been removed. The
  pack uses a single in-memory mutation probe to make the
  consequence-or-no distinction legible. It does not enumerate queues,
  retries, webhooks, caches, sub-agents or scheduled jobs;
- semantic truth from cryptographic integrity. Tamper detection proves
  that a trace changed since it was written; it does not prove that what
  was originally written was true;
- an independently implemented verifier;
- a new policy engine or identity platform;
- TrinityOS architecture disclosure or any claim derived from
  non-public material.

The pack is demonstrated only on the paths exercised by the included
scenarios and tests.

## Public disclosure boundary

This repository contains only:

- the public concepts already present in execution-gate-six;
- ordinary engineering techniques;
- the bounded temporal extension defined above.

It does not contain protected operators, private receipt schemas, private
policy language, private routing rules, private authority tokens, internal
documentation, internal collaboration material, or architecture inferred
from non-public discussions.

## License

Apache-2.0. See [LICENSE](LICENSE).
