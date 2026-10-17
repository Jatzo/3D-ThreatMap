from datetime import datetime, timedelta, timezone

import pytest

from backend.classify.session import SessionRecord
from backend.simulator import AttackSimulator

START = datetime(2019, 5, 18, tzinfo=timezone.utc)


@pytest.fixture
def make_record():
    """Build a session record, by default a bare connection with no login."""

    def make(**changes):
        fields = {
            "event_id": "evt_000001",
            "started": START,
            "country": "Ireland",
            "city": "Macroom",
            "login_attempts": 0,
            "logins_succeeded": 0,
            "tunnel_requests": 0,
        }
        return SessionRecord(**(fields | changes))

    return make


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
