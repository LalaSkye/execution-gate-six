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

__all__ = [
    "Gate", "Decision", "Verdict", "Request", "Receipt",
    "StateStore", "NonceStore", "InMemoryStateStore", "InMemoryNonceStore",
]
__version__ = "0.2.0"
