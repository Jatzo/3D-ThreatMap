from datetime import datetime, timedelta, timezone

import pytest

from backend.simulator import AttackSimulator

START = datetime(2019, 5, 18, tzinfo=timezone.utc)


@pytest.fixture
def write_replay(tmp_path):
    """Write a replay file whose events happen `offsets` seconds after START."""

    def write(offsets, real=True, name="replay.jsonl"):
        simulator = AttackSimulator(seed=5)
        lines = []
        for number, offset in enumerate(offsets, start=1):
            when = START + timedelta(seconds=offset)
            event = simulator.next_event(now=when)
            update = {"id": f"evt_{number:06d}", "original_ts": when, "source": "replay"}
            if real:
                update |= {
                    "simulated": False,
                    "dataset": "Test dataset",
                    "src": event.src.model_copy(update={"ip": None}),
                }
            lines.append(event.model_copy(update=update).model_dump_json())
        path = tmp_path / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    return write
