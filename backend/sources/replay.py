"""Replay a file of events, one JSON event per line, made by tools/convert_cyberlab.py."""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from ..models import AttackEvent

# The page falls back to its own demo if no event arrives for 3.5 seconds, so a long quiet
# stretch in the original data is shortened to this.
MAX_GAP_SECONDS = 2.0
# A file whose events share one timestamp would otherwise loop without ever pausing.
MIN_GAP_SECONDS = 0.02


class ReplayFileError(ValueError):
    """The replay file is missing, empty or not in the expected format."""


class ReplaySource:
    def __init__(
        self,
        path: Path,
        speed: float = 1.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if speed <= 0:
            raise ReplayFileError(
                "The replay speed must be above 0, for example TM_REPLAY_SPEED=10."
            )
        self._path = path
        self._speed = speed
        self._sleep = sleep
        self.mode = self._check_file()

    def _read_events(self) -> Iterator[AttackEvent]:
        try:
            handle = self._path.open(encoding="utf-8")
        except OSError as error:
            raise ReplayFileError(
                f"Cannot open the replay file {self._path} ({error.strerror}). Set TM_REPLAY_FILE "
                "to a file made by tools/convert_cyberlab.py."
            ) from error
        with handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    yield AttackEvent.model_validate_json(line)
                except ValidationError as error:
                    first = error.errors()[0]
                    raise ReplayFileError(
                        f"Line {number} of {self._path} is not a valid event: "
                        f"{first['msg']} (field: {'.'.join(str(part) for part in first['loc'])})."
                    ) from error

    def _check_file(self) -> str:
        """Read the whole file once so a bad file stops the server at start-up."""
        count = 0
        any_real = False
        for number, event in enumerate(self._read_events(), start=1):
            count += 1
            any_real = any_real or not event.simulated
            # Pausing by the difference of a naive and an aware time would crash mid-replay.
            if (event.original_ts or event.ts).tzinfo is None:
                raise ReplayFileError(
                    f"Event {number} of {self._path} has a time with no time zone. "
                    "Write times like 2019-05-18T00:00:16Z."
                )
        if count == 0:
            raise ReplayFileError(f"The replay file {self._path} has no events in it.")
        return "replayed" if any_real else "simulated"

    def _gap(self, earlier: datetime, later: datetime) -> float:
        seconds = (later - earlier).total_seconds() / self._speed
        return min(max(seconds, MIN_GAP_SECONDS), MAX_GAP_SECONDS)

    async def stream(self) -> AsyncIterator[AttackEvent]:
        """Yield the file's events with their original gaps, then start again from the top."""
        previous: datetime | None = None
        for lap in itertools.count(1):
            for event in self._read_events():
                happened = event.original_ts or event.ts
                if previous is not None:
                    await self._sleep(self._gap(previous, happened))
                previous = happened
                # Ids are prefixed with the lap so a second pass never repeats an id.
                yield event.model_copy(
                    update={"id": f"p{lap}_{event.id}", "ts": datetime.now(timezone.utc)}
                )
