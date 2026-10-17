# THREAT//MAP

A 3D cyber threat map: glowing attack arcs on a rotating globe, a live event feed and running stats, driven by a Python (FastAPI) backend that streams events over WebSockets.

> **Data note:** every event is **synthetic**. Source IPs come from `198.18.0.0/15`, a range reserved for network benchmarking that is never routable on the public internet, so no real host is shown. The cities, weights and attack mix are made up for illustration and are not a measurement of anything.

<!-- Demo GIF goes here: docs/demo.gif -->

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

| Variable  | Default | Meaning                                                       |
|-----------|---------|---------------------------------------------------------------|
| `TM_RATE` | `2.0`   | Average simulated events per second. Must be above 0.         |
| `TM_SEED` | unset   | Integer seed for a reproducible sequence of attack types, cities and ports |

## Putting it on your website (no server needed)

`frontend/index.html` is one file with no build step. When it cannot reach the backend (static hosting, or `?demo` in the URL), it switches to an in-browser copy of the simulator, so you can host it on GitHub Pages, Netlify or any static site. It still loads Globe.gl, two earth textures and two fonts from public CDNs, so the visitor needs an internet connection.

```html
<iframe src="/threat-map/index.html" title="Threat map"
        style="width:100%;height:640px;border:0;border-radius:12px" loading="lazy"></iframe>
```

Optional URL parameters for demo mode: `?demo` forces it, `?rate=5` sets events per second (0.2 to 15).

## How it works

```
AttackSimulator ──► Hub (counters + recent buffer) ──► WebSocket /ws ──► Globe.gl frontend
 (Poisson arrivals)        │
                           ├─► GET /api/stats
                           ├─► GET /api/events/recent?limit=50
                           └─► GET /api/health
```

The page draws from the WebSocket stream only. Its stats panel is counted in the browser from the events it has received since the page loaded. `/api/stats` and `/api/events/recent` are separate: they report totals since the server started, and the page does not call them.

Each event follows one schema (`backend/models.py`) and includes a MITRE ATT&CK technique:

```json
{
  "id": "evt_000123",
  "ts": "2026-10-17T12:40:00.123456Z",
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

The server writes `ts` with microseconds. The in-browser demo simulator writes milliseconds, and its ids look like `demo_12`.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

There are 15 tests. They cover the simulator (valid events, the same seed giving the same attack type, city, target and port, the reserved IP range, arc geometry), the API and WebSocket stream, and one frontend check: every backend `attack_type` key appears as text in `frontend/index.html`. That check does not compare labels, weights, ports or MITRE data, so the two catalogues can still drift apart. If you change `backend/catalog.py`, change the catalogue in `frontend/index.html` by hand.

## What is real, simulated and unverified

Checked on 17 October 2026:

- `ruff check .` passes and `pytest -q` passes (15 tests) on Python 3.13 with the newest versions of the dependencies.
- The server starts with `uvicorn backend.main:app` and the page connects to it. In one embedded browser at 1440, 800 and 375 px wide, the globe, arcs, impact rings, feed and stats animate, clicking a feed item turns the globe to that source, nothing scrolls sideways, and the page loads its scripts and textures without a 404.
- With the server stopped (page served by a plain static file server), and with `?demo`, the page falls back to the in-browser simulator and says so in its badge.

Simulated:

- Every event, including cities, attack mix, usernames, ports and the 198.18.0.0/15 source IPs. Nothing is read from a network, a honeypot or a feed.
- The target sites ("London", "Oregon" and so on) are fictional sensors.

Not verified:

- The Docker image has not been built.
- The GitHub Actions workflow (Python 3.10 and 3.12) has not been seen running. Only 3.13 was run locally.
- Opening `index.html` straight from disk (`file://`), Firefox, Safari and real phones.
- Frame rate. The embedded browser used for testing ran at about 20 frames a second, so feed items faded in slowly there.
- The CDN files are not pinned to an exact version and have no integrity hashes. On the test date `globe.gl@2` resolved to 2.46.2.

## Project layout

```
backend/    catalog.py (reference data) · models.py · simulator.py · main.py
frontend/   index.html (UI + in-browser demo simulator)
tests/      simulator and API tests
.github/    CI workflow (ruff + pytest)
```

## Security notes

The frontend builds all DOM with `textContent` and never `innerHTML`, so a hostile string in a field such as a username cannot inject markup. Every value is generated locally today, so this is a precaution.

The API and WebSocket have no authentication, origin check or rate limit. Do not expose the server to the public internet as it stands. The page also loads third-party scripts without integrity hashes (see above).
