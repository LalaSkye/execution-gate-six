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
gate. It applies fixture-supplied transitions (advance simulated time,
mutate live state, remove a principal from the recognised set, narrow
granted scopes, resubmit a request) and records what the existing gate
decides at each step. It does not introduce a second authority model.

## Bounded claim

On the five included deterministic scenarios, the pack identifies and
replays the first step at which an initially admissible request becomes
inadmissible under one of the existing canonical properties:

| Scenario              | Property the trace expects to fail |
|-----------------------|------------------------------------|
| fresh_then_stale      | Freshness                          |
| authority_removed     | Authority                          |
| scope_narrowed        | Scope                              |
| state_drift           | State                              |
| replay_after_allow    | Replay                             |

Every DENY step leaves the in-memory mutation probe unchanged. Every
replay attempt produces no additional mutation. Each evaluation step is
written as a JSONL record with a previous-record hash plus a record hash;
any single-field tamper, record removal or record reorder breaks
verification.

The gate's per-step verdict is the canonical truth. Predicates are
independent, so a single step may legitimately name multiple failed
properties (for example, a stale grant that has also already been
consumed will fail both Freshness and Replay). The trace records all
failures faithfully; tests assert containment of the expected property
rather than exclusive equality.

## Non-claims

This work does not claim:

- certification or accreditation;
- production deployment or enterprise readiness;
- compliance with any specific regulation;
- complete authorisation, including identity management, key management,
  delegation graphs, multi-tenant isolation or audit-log archival;
- continuous enterprise monitoring;
- universal coverage of authority change. The five scenarios are
  representative, not exhaustive;
- proof that every effect-capable execution path has been removed. The
  pack uses a single in-memory mutation probe to make the
  consequence-or-no distinction legible. It does not enumerate queues,
  retries, webhooks, caches, sub-agents or scheduled jobs;
- semantic truth from cryptographic integrity. Tamper detection proves
  that a trace changed since it was written; it does not prove that what
  was originally written was true;
- a new policy engine, identity system or governance platform;
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
