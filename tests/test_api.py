import base64
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.catalog import ATTACK_TYPES
from backend.classify.taxonomy import ABSTAIN, KEYS
from backend.main import create_app
from backend.models import AttackEvent
from backend.sources import ReplaySource

INDEX = Path(__file__).resolve().parent.parent / "frontend" / "index.html"


def test_health_reports_simulated_mode():
    with TestClient(create_app(rate=300, seed=1)) as client:
        data = client.get("/api/health").json()
        assert data["status"] == "ok"
        assert data["mode"] == "simulated"


def test_recent_and_stats_fill_up():
    with TestClient(create_app(rate=300, seed=1)) as client:
        time.sleep(0.4)
        recent = client.get("/api/events/recent", params={"limit": 10}).json()
        assert 0 < len(recent) <= 10
        AttackEvent.model_validate(recent[0])
        # newest first
        assert recent[0]["id"] >= recent[-1]["id"]

        stats = client.get("/api/stats").json()
        assert stats["events_total"] >= len(recent)
        assert stats["top_countries"]
        assert set(stats["by_attack_type"]) <= set(ATTACK_TYPES)


def test_recent_limit_is_validated():
    with TestClient(create_app(rate=1)) as client:
        assert client.get("/api/events/recent", params={"limit": 0}).status_code == 422
        assert client.get("/api/events/recent", params={"limit": 10_000}).status_code == 422


def test_websocket_streams_valid_events():
    with TestClient(create_app(rate=300, seed=3)) as client:
        with client.websocket_connect("/ws") as ws:
            events = [AttackEvent.model_validate(ws.receive_json()) for _ in range(3)]
        assert len({e.id for e in events}) == 3


def test_index_is_served():
    with TestClient(create_app(rate=1)) as client:
        res = client.get("/")
        assert res.status_code == 200
        assert "THREAT" in res.text


def test_frontend_knows_every_backend_attack_type():
    html = INDEX.read_text(encoding="utf-8")
    for key in ATTACK_TYPES:
        assert f"{key}:" in html, f"frontend catalog is missing {key}"


def test_frontend_builds_the_page_without_innerhtml():
    html = INDEX.read_text(encoding="utf-8")
    assert not re.search(r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write", html)


def test_frontend_knows_every_session_class_and_shows_the_analysis_as_text():
    html = INDEX.read_text(encoding="utf-8")
    for key in (*KEYS, ABSTAIN):
        assert f"{key}:" in html, f"frontend is missing the session class {key}"
    assert "Session analysis" in html
    assert "note" not in html.split("function showDetail")[1].split("function addTicker")[0]


def test_frontend_has_a_replay_badge_and_guards_its_lookups():
    html = INDEX.read_text(encoding="utf-8")
    assert "REPLAYED PUBLIC DATA" in html
    assert "Object.hasOwn(CATALOG" in html


def _embedded_pngs(html: str) -> list[bytes]:
    encoded = re.findall(r"data:image/png;base64,([A-Za-z0-9+/=]+)", html)
    return [base64.b64decode(item) for item in encoded]


def _png_chunk_types(data: bytes) -> list[str]:
    types, position = [], 8
    while position < len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        types.append(data[position + 4 : position + 8].decode("ascii"))
        position += 12 + length
    return types


def test_the_page_carries_a_favicon_and_a_header_mark_made_of_plain_pixels():
    html = INDEX.read_text(encoding="utf-8")
    assert 'rel="icon" href="data:,"' not in html
    images = _embedded_pngs(html)
    assert len(images) == 2, "expected one favicon and one header mark"
    for data in images:
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        # Image files can carry hidden provenance and editing data in extra chunks.
        assert set(_png_chunk_types(data)) <= {"IHDR", "PLTE", "tRNS", "IDAT", "IEND"}


def test_the_credit_opens_in_a_new_tab_and_leaves_the_status_line_alone():
    html = INDEX.read_text(encoding="utf-8")
    link = re.search(r'<a class="credit"[^>]*>', html)
    assert link is not None
    assert 'target="_blank"' in link.group(0)
    assert 'rel="noopener"' in link.group(0)
    # The replay and simulator wording rewrites this element, so the credit must not live in it.
    assert '<div class="sub" id="sub">live attack telemetry</div>' in html


def test_replayed_data_is_reported_as_real_by_health_and_the_stream(write_replay):
    source = ReplaySource(write_replay([0, 1, 2]), speed=1000)
    with TestClient(create_app(source=source)) as client:
        assert client.get("/api/health").json()["mode"] == "replayed"
        with client.websocket_connect("/ws") as ws:
            events = [AttackEvent.model_validate(ws.receive_json()) for _ in range(2)]
    for event in events:
        assert event.simulated is False
        assert event.src.ip is None
        assert event.dataset == "Test dataset"


def test_a_zero_event_rate_stops_the_server_at_start_up():
    with pytest.raises(ValueError, match="above 0"):
        create_app(rate=0)


def test_an_unknown_source_stops_the_server_at_start_up(monkeypatch):
    monkeypatch.setenv("TM_SOURCE", "feed")
    with pytest.raises(ValueError, match="TM_SOURCE must be"):
        create_app()


def test_replay_without_a_file_stops_the_server_at_start_up(monkeypatch):
    monkeypatch.setenv("TM_SOURCE", "replay")
    monkeypatch.delenv("TM_REPLAY_FILE", raising=False)
    with pytest.raises(ValueError, match="TM_REPLAY_FILE"):
        create_app()
