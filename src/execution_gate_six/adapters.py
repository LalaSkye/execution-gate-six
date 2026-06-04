"""Pluggable adapters for the two pieces of mutable world the gate touches:
the live state store and the replay (nonce) store.

Both are defined as Protocols so callers can back them with anything —
a dict, Redis, a database — without the gate knowing. Defaults are
in-memory and fail-closed: a store that errors causes the relevant
predicate to DENY (handled in Gate.check).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class StateStore(Protocol):
    """Reads *live* state at the instant of the gate decision."""

    def read(self, key: str) -> str:
        """Return the current value for key, or a sentinel if missing.

        Must never raise for a missing key — return a sentinel like
        '<missing>' so the state predicate denies on mismatch rather than
        crashing. Raising is treated by the gate as fail-closed DENY.
        """
        ...


@runtime_checkable
class NonceStore(Protocol):
    """Tracks consumed nonces for replay protection."""

    def seen(self, nonce: str) -> bool:
        """Return True if the nonce has already been consumed."""
        ...

    def consume(self, nonce: str) -> None:
        """Mark a nonce as consumed. Called only for ALLOWed requests."""
        ...


class InMemoryStateStore:
    """Default StateStore backed by a dict. For tests and single-process use."""

    def __init__(self, initial: dict[str, str] | None = None, missing: str = "<missing>") -> None:
        self._data: dict[str, str] = dict(initial or {})
        self._missing = missing

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def read(self, key: str) -> str:
        return self._data.get(key, self._missing)


class InMemoryNonceStore:
    """Default NonceStore backed by a set. For tests and single-process use.

    Not durable across restarts — swap for a persistent backend in
    production so replay protection survives a process crash.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def consume(self, nonce: str) -> None:
        self._seen.add(nonce)
