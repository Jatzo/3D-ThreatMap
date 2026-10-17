# THREAT//MAP

A 3D cyber threat map: glowing attack arcs on a rotating globe, a live event feed and running stats, driven by a Python (FastAPI) backend that streams events over WebSockets. By default every event is simulated. The server can also replay a day of real, public honeypot data, and a classifier can say what each replayed session was trying to do.

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

A bad setting stops the server at start-up with a message saying what to change. The server never needs an API key. Only `tools/classify_sessions.py --llm` does (see [Classifying sessions](#classifying-sessions)).

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
- Never written to the replay file: passwords, commands, file URLs, and the dataset's hashed source addresses and sensor names.
- The colour category on the page comes from the session's class (see [Classifying sessions](#classifying-sessions)). The detail line comes from a fixed template, not from raw data.
- Port is set to 22 because the dataset does not record it.
- The target of each arc is one of the fictional sensors in `backend/catalog.py`, because the dataset does not say where its honeypots were. The footer says so.
- Sessions with no location (308 of 7,465 on the day tested) are dropped.
- It refuses a day file over about 500 MB unzipped. The largest days are around 3.7 GB unzipped and would need a streaming JSON reader, which this project does not include.

How the replay behaves: the gaps between events follow the original times divided by `TM_REPLAY_SPEED`. A gap longer than 2 seconds is shortened to 2, because the page falls back to its built-in demo if nothing arrives for 3.5 seconds. A gap shorter than 0.02 seconds is raised to 0.02 so a burst cannot spin the CPU. When the file ends it starts again, with ids prefixed by the lap (`p2_evt_000001`). The feed shows when each event happened in the original data, and the stats say they count replayed events.

To see replay without downloading anything, use `tests/fixtures/replay_sample.jsonl`. It is synthetic, so the page labels it simulated.

## Classifying sessions

Each replayed session can be classified into one of six classes. Most sessions show more than one behaviour, so the classes are in a fixed order and the first one that fits wins. The table is in `backend/classify/taxonomy.py` and feeds the rules, the model's prompt and answer format, the labelling guide, the evaluation and the page.

| Order | Class | ATT&CK technique | Colour on the page |
|---|---|---|---|
| 1 | `malware_delivery`: a file was downloaded, or a command tries to fetch one (wget, curl, tftp, ftpget) | T1105 Ingress Tool Transfer | malware dropper |
| 2 | `post_login_commands`: a login worked and commands ran, with no download or fetch | T1059.004 Unix Shell | SSH brute force |
| 3 | `proxy_tunnelling`: port forwarding was requested, with none of the above | T1572 Protocol Tunneling | SSH brute force |
| 4 | `credential_guessing`: logins were tried, with none of the above | T1110.001 Password Guessing | SSH brute force |
| 5 | `scan_probe`: a connection with no login and no port forwarding | T1046 Network Service Discovery | port scan |
| 6 | `other`: nothing fits (a person or the model may say this, the rules never do) | none | port scan |

The technique IDs were checked against attack.mitre.org on 17 October 2026. A verdict of `abstain` means the model declined, ran out of room or gave an unusable answer. It is not the same as `other`.

**How it works.** `tools/convert_cyberlab.py --sessions` writes a cleaned record per session next to the replay file. A record never holds a password. Text from attackers has control characters and angle brackets removed, each command or URL is cut at 200 characters (so a fetch hidden after that point is not seen by the rules, a person or the model), URLs and addresses are written with brackets (`hxxp://203[.]0[.]113[.]9/x`), a `user:password@` inside a URL is removed, and a command that may carry a credential is replaced by a placeholder. The rules classifier reads a record and costs nothing. The model classifier is optional. `tools/classify_sessions.py` can write both verdicts into a copy of the replay file, and clicking a feed item on the page then opens a panel showing each verdict's class, technique and, for the rules, a fixed reason. The model's free-text explanation stays in local reports, because it can quote commands and URLs, and the event schema refuses to carry it.

```bash
pip install -r requirements-ai.txt        # only needed for --llm
python -m tools.convert_cyberlab cyberlab_2019-05-18.json.gz replay.jsonl --sessions local/sessions.jsonl
python -m tools.make_label_pack --sessions local/sessions.jsonl        # writes local/label_sheet.csv
# fill in the label column of local/label_sheet.csv, using local/labelling_guide.md
python -m tools.classify_sessions --sessions local/sessions.jsonl --key local/label_key.csv --dry-run
python -m tools.classify_sessions --sessions local/sessions.jsonl --key local/label_key.csv --llm
python -m tools.evaluate --labels local/label_sheet.csv --key local/label_key.csv \
    --strata local/label_strata.json --verdicts local/verdicts.jsonl
python -m tools.classify_sessions --sessions local/sessions.jsonl --enrich-replay replay.jsonl \
    --enriched-out local/replay_enriched.jsonl
```

Everything under `local/` is ignored by git.

**What leaves your machine.** Only with `--llm`, and only for the sessions you select, each session's evidence is sent to the Anthropic API: login attempt counts, the usernames tried, the commands run (credential-looking ones withheld, URLs and addresses with brackets), files downloaded (with brackets), port-forward count, session length and client software. Not sent: passwords, place, time, the dataset's hashed identifiers. I have not checked Anthropic's data retention terms for your account. The key is read from `ANTHROPIC_API_KEY` or an `ant auth login` profile in your own shell and is never stored in this project.

**Spend.** The default model is `claude-opus-5-5` (`--model` changes it to `claude-sonnet-5-5` or `claude-haiku-5-5`). Run `--dry-run` first: it prints how many calls are needed and the most they can cost at list price, counting every input character as a token and the full output allowance as used, and calls nothing. `--max-spend` (default $5) is a hard cap: a run stops before any call that could take the total over it. The client makes no automatic retries, because a retried request that timed out can be billed twice without the cap seeing it. A failed call becomes an abstention that is not cached, so a rerun tries it again. `--llm` needs `--key` or `--limit`, so it never starts on a whole day by accident. Answers are cached in `local/llm_cache.jsonl`, keyed on the evidence, the model, the prompt text and the answer format, so a repeat run costs nothing for sessions already done and a changed prompt never reuses old answers.

**Prompt injection.** Session text comes from attackers. It sits between `<session>` markers (angle brackets are stripped from it), the prompt says to treat it as data, the answer is limited to a class key and a short note, and the technique is taken from the table, never from the model. A refusal or an unusable answer becomes `abstain`.

**Evaluation.** Measured once, on 17 October 2026, on 50 sessions of one day. Read "What these numbers do and do not show" below before quoting any of it. The method:

- The sheet is 50 sessions sampled from the day, stratified on what each session did (download, commands, port forwarding, login only, connect only), with strata of 12 sessions or fewer taken whole. It shows exactly the evidence the model sees, and no classifier output.
- The 50 labels follow the labelling guide and were written from the sheet alone. I reviewed all 50 against the guide and agreed with every one. No independent analyst wrote or checked them. They were written after the model had been run on the sheet. At that point only the count of the model's answers per class was known, and no answer for a single session. The labelling guide, the rules, the model prompt and the labels all come from the same source, so the labels are not independent of the classifiers.
- `tools/evaluate.py` reports accuracy on the sample, accuracy re-weighted to the real size of each stratum, the result inside each stratum, per-class precision, recall and F1, a confusion matrix and the abstentions, which count as misses. It gives no confidence interval, because a plain formula is wrong for a stratified sample. With 50 labels, read the per-stratum counts.
- The model prompt is frozen before it is run on the labelled sheet. If it is changed afterwards, the README must say the numbers were tuned on the test set.

| Classifier | Labelled sessions | Accuracy on the sample | Re-weighted accuracy | Macro F1 | Abstentions |
|---|---|---|---|---|---|
| Rules | 50 | 100% | 100% | 100% | 0 |
| Model (`claude-opus-5-5`, prompt `v1`) | 50 | 96% (48 of 50) | 100% | 98% | 2 |

By stratum, the rules were right on every session. The model was right on every session it answered. Its two abstentions were both in the commands stratum, where it got 9 of 11. Per class, the model's recall was 100% for every class except commands after login, at 82%, and its precision was 100% for every class. The `other` class has no labels.

**What these numbers do and do not show.**

- The rules score 100% because the labels were written from the same guide the rules implement. That figure says nothing about the rules.
- The model matched the labels whenever it answered. That shows it applies the written guide the way the labels do. It does not show the guide is right, that the classes match real attacker intent, or that the model would find an unfamiliar threat.
- The labels, the rules and the model all work from the same guide and the same fields, so their mistakes are likely to be correlated. Labels from an independent person are needed for a real test.
- Almost every session on this day has an obvious structure (a count of logins, forwards or downloads), so the classes are easy. Few kinds of behaviour appear, and one day is not a sample of the dataset.
- The re-weighted accuracy rounds to 100% because the two largest strata, login only and connect only, hold about 98% of the sessions. It hides the commands stratum. Read the per-stratum counts.
- With 50 labels there is no confidence interval worth quoting, and the report gives none.
- The model's two refusals are recorded as misses. Refusals are likely on sessions that hold shell commands.

**Status of the model path.** On 17 October 2026 it was run on the 50 sheet sessions with `claude-opus-5-5`. The request format (low effort plus a JSON schema) was accepted, 48 sessions got a usable answer, and 2 were declined by the model and recorded as `abstain`. Both were in the commands stratum, whose sessions hold shell commands. The run cost $0.13: 28 calls, with 22 sessions sharing the cached answer of a session that had identical evidence. The evaluation above used its answers.

## Putting it on your website (no server needed)

`frontend/index.html` is one file with no build step. When it cannot reach the backend (static hosting, or `?demo` in the URL), it switches to an in-browser copy of the simulator, so you can host it on GitHub Pages, Netlify or any static site. It still loads Globe.gl, two earth textures and two fonts from public CDNs, so the visitor needs an internet connection. Replay and classification need the server.

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
  "original_ts": null,
  "analysis": null
}
```

The server writes `ts` with microseconds. The in-browser demo simulator writes milliseconds, its ids look like `demo_12`, and its `source` is `browser`. For replayed data `simulated` is `false`, `src.ip` is `null`, `dataset` holds the credit and `original_ts` is the time in the original data. `analysis` is `null` unless `tools/classify_sessions.py` has added the rules verdict and, if it was run, the model's verdict. The model refuses an event that has a `dataset` and is marked simulated, an `attack_type` that is not in the catalogue, a verdict whose class is not in the table, and an analysis carrying the model's free text.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

There are 108 tests. They cover the simulator (valid events, the same seed giving the same attack type, city, target and port, the reserved IP range, arc geometry), the event schema, the replay source (pauses, long and negative gaps, laps, bad and missing files), the converter (what it keeps, what it never outputs, the size limit), the session records (no passwords, credential-looking commands withheld, URLs written with brackets, limits), the rules, the labelling pack (stratification, whole small strata, a sheet with no classifier output), the evaluation arithmetic against hand counts, the model classifier against a stand-in client (answer handling, refusals, caching, the spend cap, injection markers), the API and WebSocket stream in both modes, and a few frontend checks: every backend `attack_type` key and session class appears as text in `frontend/index.html`, the page never uses `innerHTML`, and the replay badge exists. The frontend check does not compare labels, weights, ports or MITRE data, so the two catalogues can still drift apart. If you change `backend/catalog.py`, change the catalogue in `frontend/index.html` by hand.

## What is real, simulated and unverified

Checked on 17 October 2026:

- `ruff check .` passes and `pytest -q` passes (108 tests) on Python 3.13 with the newest versions of the dependencies.
- The server starts with `uvicorn backend.main:app` and the page connects to it. In one embedded browser at 1440, 800 and 375 px wide, the globe, arcs, impact rings, feed and stats animate, clicking a feed item turns the globe to that source, nothing scrolls sideways, and the page loads its scripts and textures without a 404.
- With the server stopped (page served by a plain static file server), and with `?demo`, the page falls back to the in-browser simulator and says so in its badge.
- One real day file (`cyberlab_2019-05-18.json.gz`) was converted to 7,157 events and replayed at 20 times speed. The badge, footer and stat labels changed to the replay wording at 375 and 1440 px, and the feed showed the original May 2019 times. With the page left open, swapping the replay server for the simulator server, or stopping it so the page fell back to its demo, put the synthetic wording back and reset the totals. Converted output was searched for passwords, URLs and the dataset's identifiers and held none.
- The rules classified all 7,157 sessions of that day (2,087 scan or probe, 4,953 credential guessing, 77 port forwarding, 11 commands after login, 29 malware delivery), and the analysis panel opened on a feed item at 375 and 1440 px. In that browser check the model verdicts were made-up placeholders, not real output.

Real:

- In replay mode, the times, cities, countries, usernames and the sequence of sessions come from the dataset.

Simulated:

- In the default mode, every event, including cities, attack mix, usernames, ports and the 198.18.0.0/15 source IPs. Nothing is read from a network, a honeypot or a feed.
- In both modes, the target sites ("London", "Oregon" and so on) are fictional sensors, and in replay the port is assumed.

Not verified:

- Accuracy was measured on 50 sessions of one day against labels that follow the guide and that no independent analyst wrote or checked, so the figures are not independent evidence that either classifier is right.
- Only one day of the dataset was tried. Other days, and the two Cowrie versions the dataset spans, may differ. The Cowrie message formats the converter reads come from that one day.
- The classes and their order are my reading of the data. The dataset's city lookups were not checked for accuracy.
- The Docker image has not been built. It does not include `tools/`, so run the converter outside the container.
- The GitHub Actions workflow (Python 3.10 and 3.12) has not been seen running. Only 3.13 was run locally.
- Opening `index.html` straight from disk (`file://`), Firefox, Safari and real phones.
- Frame rate. The embedded browser used for testing ran at about 20 frames a second, so feed items faded in slowly there.
- The CDN files are not pinned to an exact version and have no integrity hashes. On the test date `globe.gl@2` resolved to 2.46.2.

## Project layout

```
backend/    catalog.py (reference data) · models.py · simulator.py · main.py
            sources/ (event source interface, simulator source, replay source)
            classify/ (taxonomy, session records, rules, model classifier)
frontend/   index.html (UI + in-browser demo simulator)
tools/      convert_cyberlab.py · make_label_pack.py · classify_sessions.py · evaluate.py
tests/      unit and API tests; fixtures/ holds a synthetic replay file
.github/    CI workflow (ruff + pytest)
```

`requirements.txt` runs the server, `requirements-dev.txt` adds the tests and ruff, and `requirements-ai.txt` adds the `anthropic` package for the model classifier only.

## Security notes

The frontend builds all DOM with `textContent` and never `innerHTML`, so a hostile string in a field such as a username cannot inject markup. A test checks this.

In replay mode the feed shows usernames from real attackers. People sometimes type a password into a username field, so usernames are cut to 32 printable characters and treated as untrusted text, but you may still see one. Passwords are never read, and commands and URLs never reach the page. The dataset's authors pseudonymised its public addresses, and the converter never reads those pseudonyms.

Commands and URLs are read into the local session records, with credential-looking commands withheld and URLs written with brackets. Those files stay under `local/`. The withholding rule is a pattern match and can miss a credential written in an unusual way, so treat `local/sessions.jsonl` as sensitive.

The API and WebSocket have no authentication, origin check or rate limit. Do not expose the server to the public internet as it stands. The page also loads third-party scripts without integrity hashes (see above).
