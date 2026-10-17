"""The event source interface and the built-in simulator source."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from ..models import AttackEvent
from ..simulator import AttackSimulator


class EventSource(Protocol):
    # "simulated" or "replayed": shown by /api/health and used to label the page.
    mode: str

    def stream(self) -> AsyncIterator[AttackEvent]: ...


class SimulatorSource:
    mode = "simulated"

    def __init__(self, rate: float, seed: int | None = None) -> None:
        if rate <= 0:
            raise ValueError("The event rate must be above 0, for example TM_RATE=2.0.")
        self._rate = rate
        self._simulator = AttackSimulator(seed=seed)

    def stream(self) -> AsyncIterator[AttackEvent]:
        return self._simulator.stream(self._rate)
