import csv
import json

import pytest

from backend.classify.session import evidence
from backend.classify.taxonomy import KEYS
from tools.make_label_pack import STRATA, allocate, build_pack, stratum, write_pack


def population(make_record, counts):
    """Records for each stratum, with numbered event ids."""
    shapes = {
        "download": dict(downloads=["hxxp://a[.]b/x"], login_attempts=1),
        "commands": dict(commands=["id"], commands_total=1, login_attempts=1),
        "tunnelling": dict(tunnel_requests=2, login_attempts=1),
        "login_only": dict(login_attempts=2),
        "connect_only": dict(),
    }
    records = []
    for name, number in counts.items():
        for _ in range(number):
            records.append(make_record(event_id=f"evt_{len(records) + 1:06d}", **shapes[name]))
    return records


def test_a_session_is_placed_by_what_it_did_not_by_a_classifier(make_record):
    for name, expected in (
        ("download", "download"),
        ("commands", "commands"),
        ("tunnelling", "tunnelling"),
        ("login_only", "login_only"),
        ("connect_only", "connect_only"),
    ):
        assert stratum(population(make_record, {name: 1})[0]) == expected


def test_small_strata_are_taken_whole_and_the_rest_share_what_is_left():
    sizes = {"download": 29, "commands": 11, "tunnelling": 77, "login_only": 4953}
    taken = allocate(sizes | {"connect_only": 2087}, 50)
    assert taken["commands"] == 11
    assert sum(taken.values()) == 50
    assert max(taken[k] for k in ("download", "tunnelling", "login_only", "connect_only")) <= 10


def test_a_stratum_smaller_than_its_share_gives_the_rest_to_the_others():
    taken = allocate({"a": 3, "b": 500, "c": 500}, 50)
    assert taken == {"a": 3, "b": 23, "c": 24}


def test_too_many_small_strata_for_the_sample_size_is_refused():
    with pytest.raises(ValueError, match="bigger than the sample size"):
        allocate({"a": 12, "b": 12, "c": 12}, 30)


def test_the_same_seed_picks_the_same_sessions(make_record):
    records = population(make_record, {"commands": 11, "login_only": 80, "connect_only": 80})
    first = build_pack(records, 30, seed=7)
    again = build_pack(records, 30, seed=7)
    other = build_pack(records, 30, seed=8)
    ids = lambda pack: [r.event_id for _, r in pack["chosen"]]  # noqa: E731
    assert ids(first) == ids(again)
    assert ids(first) != ids(other)
    assert len(ids(first)) == 30


def test_the_sheet_shows_the_evidence_and_no_classifier_output(make_record, tmp_path):
    records = population(make_record, {"download": 5, "commands": 5, "login_only": 60})
    write_pack(build_pack(records, 20, seed=1), tmp_path)
    with (tmp_path / "label_sheet.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == ["sheet_id", *evidence(records[0]), "label", "notes"]
    assert all(row["label"] == "" for row in rows)
    sheet = (tmp_path / "label_sheet.csv").read_text(encoding="utf-8-sig")
    assert not any(key in sheet for key in KEYS)
    assert "evt_" not in sheet
    assert "Ireland" not in sheet


def test_the_key_and_strata_files_let_the_sheet_be_scored_later(make_record, tmp_path):
    records = population(make_record, {"commands": 5, "login_only": 60, "connect_only": 60})
    write_pack(build_pack(records, 20, seed=1), tmp_path)
    with (tmp_path / "label_key.csv").open(encoding="utf-8", newline="") as handle:
        key = list(csv.DictReader(handle))
    assert [row["sheet_id"] for row in key] == [f"S{n:02d}" for n in range(1, 21)]
    assert {row["stratum"] for row in key} <= set(STRATA)
    info = json.loads((tmp_path / "label_strata.json").read_text(encoding="utf-8"))
    assert sum(info["sampled"].values()) == 20
    assert info["sizes"]["commands"] == 5
    assert "credential_guessing" in (tmp_path / "labelling_guide.md").read_text(encoding="utf-8")
