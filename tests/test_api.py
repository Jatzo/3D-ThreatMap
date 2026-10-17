import time
from pathlib import Path

from fastapi.testclient import TestClient

from backend.catalog import ATTACK_TYPES
from backend.main import create_app
from backend.models import AttackEvent

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
