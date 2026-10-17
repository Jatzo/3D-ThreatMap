import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.sources.replay import (
    MAX_GAP_SECONDS,
    MIN_GAP_SECONDS,
    ReplayFileError,
    ReplaySource,
)

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "replay_sample.jsonl"


async def collect(source, count):
    events = []
    async for event in source.stream():
        events.append(event)
        if len(events) == count:
            break
    return events


def replay(path, count, speed=1.0):
    """Replay without waiting: return the events and the pauses the source asked for."""
    pauses = []

    async def record_pause(seconds):
        pauses.append(seconds)

    source = ReplaySource(path, speed=speed, sleep=record_pause)
    return asyncio.run(collect(source, count)), pauses


def test_pauses_follow_the_original_gaps_divided_by_the_speed(write_replay):
    _, pauses = replay(write_replay([0, 1, 2.5]), count=3, speed=2)
    assert pauses == [0.5, 0.75]


def test_a_long_quiet_stretch_is_shortened(write_replay):
    _, pauses = replay(write_replay([0, 3600, 3601]), count=3)
    assert pauses == [MAX_GAP_SECONDS, 1.0]


def test_events_with_the_same_time_still_pause(write_replay):
    _, pauses = replay(write_replay([0, 0, 0]), count=3)
    assert pauses == [MIN_GAP_SECONDS, MIN_GAP_SECONDS]


def test_times_that_go_backwards_never_ask_for_a_negative_pause(write_replay):
    _, pauses = replay(write_replay([10, 0, 5]), count=3)
    assert pauses == [MIN_GAP_SECONDS, MAX_GAP_SECONDS]


def test_the_replay_starts_again_with_new_ids_after_the_last_event(write_replay):
    events, pauses = replay(write_replay([0, 1]), count=4)
    assert [e.id for e in events] == [
        "p1_evt_000001",
        "p1_evt_000002",
        "p2_evt_000001",
        "p2_evt_000002",
    ]
    assert len(pauses) == 3
    assert pauses[1] == MIN_GAP_SECONDS


def test_replayed_events_keep_their_original_time_and_get_a_fresh_one(write_replay):
    events, _ = replay(write_replay([0, 90]), count=2)
    assert events[1].original_ts == datetime(2019, 5, 18, 0, 1, 30, tzinfo=timezone.utc)
    assert abs(datetime.now(timezone.utc) - events[1].ts) < timedelta(minutes=1)


def test_replayed_events_are_marked_real_and_carry_no_address(write_replay):
    events, _ = replay(write_replay([0, 1]), count=2)
    for event in events:
        assert event.simulated is False
        assert event.dataset == "Test dataset"
        assert event.src.ip is None


def test_mode_says_replayed_for_dataset_events(write_replay):
    assert ReplaySource(write_replay([0, 1])).mode == "replayed"


def test_the_bundled_sample_is_replayed_as_simulated():
    source = ReplaySource(SAMPLE)
    assert source.mode == "simulated"
    events, _ = replay(SAMPLE, count=3)
    assert all(e.simulated and e.dataset is None for e in events)


def test_a_missing_file_stops_start_up_with_a_clear_message(tmp_path):
    with pytest.raises(ReplayFileError, match="Cannot open the replay file"):
        ReplaySource(tmp_path / "nothing.jsonl")


def test_an_empty_file_is_refused(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n", encoding="utf-8")
    with pytest.raises(ReplayFileError, match="no events"):
        ReplaySource(empty)


def test_a_bad_line_is_reported_with_its_number(write_replay):
    path = write_replay([0])
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    with pytest.raises(ReplayFileError, match="Line 2"):
        ReplaySource(path)


def test_an_unknown_attack_type_is_refused(write_replay):
    path = write_replay([0])
    event = json.loads(path.read_text(encoding="utf-8"))
    event["attack_type"] = "mystery"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(ReplayFileError, match="unknown attack_type"):
        ReplaySource(path)


def test_a_time_with_no_time_zone_is_refused(write_replay):
    path = write_replay([0])
    event = json.loads(path.read_text(encoding="utf-8"))
    event["original_ts"] = "2019-05-18T00:00:00"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(ReplayFileError, match="no time zone"):
        ReplaySource(path)


def test_a_speed_of_zero_is_refused(write_replay):
    with pytest.raises(ReplayFileError, match="speed"):
        ReplaySource(write_replay([0, 1]), speed=0)
