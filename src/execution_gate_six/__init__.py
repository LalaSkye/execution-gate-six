"""execution-gate-six: a fail-closed runtime authority gate.

Runtime enforcement in the literature checks *what* an action is.
This checks *whether the permission to perform it is still valid at the
instant of execution* — across six independent properties:

    Authority. Scope. Freshness. Replay. State. Receipt.

Any property that cannot be positively established -> DENY (fail-closed).
"""

from .gate import Gate, Decision, Verdict, Request, Receipt
from .adapters import (
    StateStore,
    NonceStore,
    InMemoryStateStore,
    InMemoryNonceStore,
)
from .temporal import (
    TRACE_VERSION,
    MutationProbe,
    TemporalScenario,
    TemporalStep,
    run_scenario,
    serialise_trace,
)
from .trace_verify import VerifyResult, load_scenario, load_trace, verify

__all__ = [
    "Gate", "Decision", "Verdict", "Request", "Receipt",
    "StateStore", "NonceStore", "InMemoryStateStore", "InMemoryNonceStore",
    "TRACE_VERSION", "MutationProbe", "TemporalScenario", "TemporalStep",
    "run_scenario", "serialise_trace",
    "VerifyResult", "load_scenario", "load_trace", "verify",
]
__version__ = "0.2.0"
