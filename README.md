# THREAT//MAP

A 3D cyber threat map: glowing attack arcs on a rotating globe, a live event feed and running stats, driven by a Python (FastAPI) backend that streams events over WebSockets. By default every event is simulated. The server can also replay a day of real, public honeypot data.

> **Data note:** in the default mode every event is **synthetic**. Source IPs come from `198.18.0.0/15`, a range reserved for network benchmarking that is never routable on the public internet, so no real host is shown. The cities, weights and attack mix are made up for illustration and are not a measurement of anything. In replay mode the page says so in its badge and footer, and credits the dataset (see [Replaying public honeypot data](#replaying-public-honeypot-data)).

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

| Variable          | Default | Meaning                                                                    |
|-------------------|---------|----------------------------------------------------------------------------|
| `TM_SOURCE`       | `sim`   | `sim` for simulated events, `replay` to replay a converted file            |
| `TM_RATE`         | `2.0`   | Average simulated events per second. Must be above 0. Simulator only.      |
| `TM_SEED`         | unset   | Integer seed for a reproducible sequence of attack types, cities and ports. Simulator only. |
| `TM_REPLAY_FILE`  | unset   | Path of the file to replay. Required when `TM_SOURCE=replay`.              |
| `TM_REPLAY_SPEED` | `1.0`   | Replay speed multiplier. Must be above 0.                                  |

A bad setting stops the server at start-up with a message saying what to change.

## Replaying public honeypot data

The server can replay one day of the CyberLab honeynet dataset: sessions recorded by Cowrie SSH honeypots at universities and companies in the EU and US between May 2019 and February 2020.

**Credit:** Sedlar, Kren, Štefanič Južnič and Volk, University of Ljubljana, "CyberLab honeynet dataset", Zenodo, [doi:10.5281/zenodo.3687527](https://doi.org/10.5281/zenodo.3687527), licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). **Changes made:** each session is reduced to one event, as described below. No endorsement by the authors is implied. The data is not in this repository: you download it yourself.

```bash
# 1. Download one day file from https://zenodo.org/records/3687527
#    (cyberlab_2019-05-18.json.gz is the smallest, 1.6 MB), then convert it:
python -m tools.convert_cyberlab cyberlab_2019-05-18.json.gz replay.jsonl

# 2. Start the server in replay mode (PowerShell: $env:TM_SOURCE = "replay", and so on):
TM_SOURCE=replay TM_REPLAY_FILE=replay.jsonl TM_REPLAY_SPEED=20 uvicorn backend.main:app
```

What the converter does, one event per session:

- Kept: when the session began, the city and country the dataset placed the source in, and the username tried (up to 32 printable characters).
- Never read or written: passwords, commands, file URLs, and the dataset's hashed source addresses and sensor names.
- Attack type, by what the session did: a file download is a malware dropper, any login attempt (with or without commands) is SSH brute force, and a connection with no login is a port scan. The detail line comes from a fixed template, not from raw data.
- Port is set to 22 because the dataset does not record it.
- The target of each arc is one of the fictional sensors in `backend/catalog.py`, because the dataset does not say where its honeypots were. The footer says so.
- Sessions with no location (308 of 7,465 on the day tested) are dropped.
- It refuses a day file over about 500 MB unzipped. The largest days are around 3.7 GB unzipped and would need a streaming JSON reader, which this project does not include.

How the replay behaves: the gaps between events follow the original times divided by `TM_REPLAY_SPEED`. A gap longer than 2 seconds is shortened to 2, because the page falls back to its built-in demo if nothing arrives for 3.5 seconds. A gap shorter than 0.02 seconds is raised to 0.02 so a burst cannot spin the CPU. When the file ends it starts again, with ids prefixed by the lap (`p2_evt_000001`). The feed shows when each event happened in the original data, and the stats say they count replayed events.

To see replay without downloading anything, use `tests/fixtures/replay_sample.jsonl`. It is synthetic, so the page labels it simulated.

## Putting it on your website (no server needed)

`frontend/index.html` is one file with no build step. When it cannot reach the backend (static hosting, or `?demo` in the URL), it switches to an in-browser copy of the simulator, so you can host it on GitHub Pages, Netlify or any static site. It still loads Globe.gl, two earth textures and two fonts from public CDNs, so the visitor needs an internet connection. Replay needs the server.

```html
<iframe src="/threat-map/index.html" title="Threat map"
        style="width:100%;height:640px;border:0;border-radius:12px" loading="lazy"></iframe>
```

Optional URL parameters for demo mode: `?demo` forces it, `?rate=5` sets events per second (0.2 to 15).

## How it works

```
EventSource ──► Hub (counters + recent buffer) ──► WebSocket /ws ──► Globe.gl frontend
(simulator or replay)     │
                          ├─► GET /api/stats
                          ├─► GET /api/events/recent?limit=50
                          └─► GET /api/health   (mode: simulated or replayed)
```

The simulator draws arrivals from a Poisson process. The page draws from the WebSocket stream only. Its stats panel is counted in the browser from the events it has received since the page loaded. `/api/stats` and `/api/events/recent` are separate: they report totals since the server started, and the page does not call them.

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
  "simulated": true,
  "source": "simulator",
  "dataset": null,
  "original_ts": null
}
```

The server writes `ts` with microseconds. The in-browser demo simulator writes milliseconds, its ids look like `demo_12`, and its `source` is `browser`. For replayed data `simulated` is `false`, `src.ip` is `null`, `dataset` holds the credit and `original_ts` is the time in the original data. The model refuses an event that has a `dataset` and is marked simulated, and refuses an `attack_type` that is not in the catalogue.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

There are 49 tests. They cover the simulator (valid events, the same seed giving the same attack type, city, target and port, the reserved IP range, arc geometry), the event schema, the replay source (pauses, long and negative gaps, laps, bad and missing files), the converter (what it keeps, what it never outputs, the size limit), the API and WebSocket stream in both modes, and a few frontend checks: every backend `attack_type` key appears as text in `frontend/index.html`, the page never uses `innerHTML`, and the replay badge exists. The frontend check does not compare labels, weights, ports or MITRE data, so the two catalogues can still drift apart. If you change `backend/catalog.py`, change the catalogue in `frontend/index.html` by hand.

## What is real, simulated and unverified

Checked on 17 October 2026:

- `ruff check .` passes and `pytest -q` passes (49 tests) on Python 3.13 with the newest versions of the dependencies.
- The server starts with `uvicorn backend.main:app` and the page connects to it. In one embedded browser at 1440, 800 and 375 px wide, the globe, arcs, impact rings, feed and stats animate, clicking a feed item turns the globe to that source, nothing scrolls sideways, and the page loads its scripts and textures without a 404.
- With the server stopped (page served by a plain static file server), and with `?demo`, the page falls back to the in-browser simulator and says so in its badge.
- One real day file (`cyberlab_2019-05-18.json.gz`) was converted to 7,157 events and replayed at 20 times speed. The badge, footer and stat labels changed to the replay wording at 375 and 1440 px, and the feed showed the original May 2019 times. With the page left open, swapping the replay server for the simulator server, or stopping it so the page fell back to its demo, put the synthetic wording back and reset the totals. Converted output was searched for passwords, URLs and the dataset's identifiers and held none.

Real:

- In replay mode, the times, cities, countries, usernames and the sequence of sessions come from the dataset.

Simulated:

- In the default mode, every event, including cities, attack mix, usernames, ports and the 198.18.0.0/15 source IPs. Nothing is read from a network, a honeypot or a feed.
- In both modes, the target sites ("London", "Oregon" and so on) are fictional sensors, and in replay the port is assumed.

Not verified:

- Only one day of the dataset was tried. Other days, and the two Cowrie versions the dataset spans, may differ.
- The attack types are my simple rule over each session, not a label from the dataset. The dataset's city lookups were not checked for accuracy.
- The Docker image has not been built. It does not include `tools/`, so run the converter outside the container.
- The GitHub Actions workflow (Python 3.10 and 3.12) has not been seen running. Only 3.13 was run locally.
- Opening `index.html` straight from disk (`file://`), Firefox, Safari and real phones.
- Frame rate. The embedded browser used for testing ran at about 20 frames a second, so feed items faded in slowly there.
- The CDN files are not pinned to an exact version and have no integrity hashes. On the test date `globe.gl@2` resolved to 2.46.2.

## Project layout

```
backend/    catalog.py (reference data) · models.py · simulator.py · main.py
            sources/ (event source interface, simulator source, replay source)
frontend/   index.html (UI + in-browser demo simulator)
tools/      convert_cyberlab.py (dataset day file to replay file)
tests/      simulator, schema, replay, converter and API tests; fixtures/ holds a synthetic replay file
.github/    CI workflow (ruff + pytest)
```

## Security notes

The frontend builds all DOM with `textContent` and never `innerHTML`, so a hostile string in a field such as a username cannot inject markup. A test checks this.

In replay mode the feed shows usernames from real attackers. People sometimes type a password into a username field, so usernames are cut to 32 printable characters and treated as untrusted text, but you may still see one. Passwords, commands and URLs are never read. The dataset's authors pseudonymised its public addresses, and the converter never reads those pseudonyms.

The API and WebSocket have no authentication, origin check or rate limit. Do not expose the server to the public internet as it stands. The page also loads third-party scripts without integrity hashes (see above).
