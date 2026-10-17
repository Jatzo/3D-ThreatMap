"""Where events come from: the built-in simulator, or a replayed file."""

from .base import EventSource, SimulatorSource
from .replay import ReplayFileError, ReplaySource

__all__ = ["EventSource", "ReplayFileError", "ReplaySource", "SimulatorSource"]
