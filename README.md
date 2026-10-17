# THREAT//MAP

A real-time 3D cyber threat map: glowing attack arcs on a rotating globe, a live event feed, and rolling stats, driven by a Python (FastAPI) backend that streams events over WebSockets.

> **Data note:** every event is **synthetic**. Source IPs come from `198.18.0.0/15`, a range reserved for network benchmarking that is never routable on the public internet, so no real host is shown. The geographic spread is illustrative, not a measurement.

<!-- Add a demo GIF here: docs/demo.gif -->

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open <http://localhost:8000>. Click any item in the live feed to fly the globe to that attacker.

Or with Docker:

```bash
docker build -t threat-map . && docker run -p 8000:8000 threat-map
```

### Configuration

| Variable  | Default | Meaning                                   |
|-----------|---------|-------------------------------------------|
| `TM_RATE` | `2.0`   | Average simulated events per second       |
| `TM_SEED` | unset   | Integer seed for a reproducible sequence  |

## Putting it on your website (no server needed)

`frontend/index.html` is fully self-contained. When it can't reach the backend (static hosting, `file://`, or `?demo` in the URL), it switches to an in-browser copy of the simulator, so you can host it on GitHub Pages, Netlify or any static site:

```html
<iframe src="/threat-map/index.html" title="Threat map"
        style="width:100%;height:640px;border:0;border-radius:12px" loading="lazy"></iframe>
```

Optional URL parameters for demo mode: `?demo` forces it, `?rate=5` sets events per second (0.2 to 15).

## How it works

```
AttackSimulator ──► Hub (stats + recent buffer) ──► WebSocket /ws ──► Globe.gl frontend
 (Poisson arrivals)        │
                           ├─► GET /api/stats
                           ├─► GET /api/events/recent?limit=50
                           └─► GET /api/health
```

Each event follows one schema (`backend/models.py`) and includes a MITRE ATT&CK technique:

```json
{
  "id": "evt_000123",
  "ts": "2026-10-17T12:40:00.123Z",
  "attack_type": "ssh_bruteforce",
  "label": "SSH brute force",
  "severity": 2,
  "port": 22,
  "service": "ssh",
  "detail": "login attempt as root",
  "username": "root",
  "mitre": { "id": "T1110.001", "name": "Password Guessing" },
  "src": { "ip": "198.18.4.77", "country": "China", "city": "Beijing", "lat": 39.9, "lng": 116.4 },
  "dst": { "name": "London", "lat": 51.51, "lng": -0.13 },
  "simulated": true
}
```

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

Tests cover the simulator (validity, determinism, reserved IP range, arc geometry), the API and WebSocket stream, and that the frontend's attack catalog stays in sync with the backend's.

## Project layout

```
backend/    catalog.py (reference data) · models.py · simulator.py · main.py
frontend/   index.html (UI + in-browser demo simulator)
tests/      simulator and API tests
.github/    CI workflow (ruff + pytest)
```

## Roadmap

- [x] **Phase 1:** simulator, FastAPI WebSocket stream, neon 3D globe
- [ ] **Phase 2:** replay real public data (published honeypot logs, abuse.ch feeds) through the same `AttackEvent` model, with GeoIP enrichment and storage
- [ ] **Phase 3:** AI layer that classifies attacker sessions, maps them to ATT&CK, explains its reasoning, and is evaluated against hand-labelled sessions
- [ ] **Phase 4:** time-slider replay, Sigma rule generation from observed behaviour, weekly AI threat report

## Security notes

The frontend builds all DOM with `textContent` (never `innerHTML`) because fields such as usernames will be attacker-controlled once real data is added in Phase 2.
