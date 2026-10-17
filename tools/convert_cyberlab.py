"""Turn one day file of the CyberLab honeynet dataset into events the server can replay.

The dataset (Sedlar, Kren, Stefanic Juznic and Volk, University of Ljubljana, CC BY 4.0,
doi:10.5281/zenodo.3687527) holds Cowrie honeypot sessions. Download one day file yourself, then:

    python -m tools.convert_cyberlab cyberlab_2019-05-18.json.gz replay.jsonl

Each session becomes one event. What is kept: when the session began, the city the dataset
placed the source in, and the username tried. What is never read or written: passwords,
commands, file URLs and the dataset's hashed source and sensor identifiers. The target of each
arc is one of the fictional sensors in backend/catalog.py, because the dataset does not say
where its honeypots were.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from backend.catalog import ATTACK_TYPES, SENSORS, Sensor
from backend.models import AttackEvent, Mitre, Source, Target

DATASET = (
    "CyberLab honeynet dataset (Sedlar et al., University of Ljubljana), "
    "CC BY 4.0, doi:10.5281/zenodo.3687527"
)
# The biggest day files are about 3.7 GB once unzipped, which json.load cannot hold in memory.
MAX_UNZIPPED_BYTES = 500_000_000
MAX_USERNAME_LENGTH = 32
# The dataset does not record the port, and Cowrie is normally reached on the SSH port.
ASSUMED_PORT = 22

LOGIN_EVENTS = {"cowrie.login.success", "cowrie.login.failed"}
COMMAND_EVENTS = {"cowrie.command.success", "cowrie.command.failed"}


class ConversionError(ValueError):
    """The input is too big or not shaped like a CyberLab day file."""


def unzipped_size(path: Path) -> int:
    """Size once unzipped. For .gz files this reads the length stored in the last four bytes."""
    if path.suffix != ".gz":
        return path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(-4, 2)
        return struct.unpack("<I", handle.read(4))[0]


def _parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _location(events: list[dict]) -> tuple[str, str, float, float] | None:
    """The first usable (country, city, lat, lng) the dataset gives for this session."""
    for event in events:
        geo = event.get("geolocation_data")
        if not isinstance(geo, dict):
            continue
        try:
            lat = float(geo["latitude"])
            lng = float(geo["longitude"])
        except (KeyError, TypeError, ValueError):
            continue
        country = geo.get("country_name")
        if not isinstance(country, str) or not -90 <= lat <= 90 or not -180 <= lng <= 180:
            continue
        city = geo.get("city_name") or geo.get("region_name") or country
        return country, str(city), lat, lng
    return None


def _username(events: list[dict]) -> str | None:
    """The username tried, preferring a login that worked. Passwords are never read."""
    logins = [e for e in events if e.get("eventid") in LOGIN_EVENTS]
    logins.sort(key=lambda e: e["eventid"] != "cowrie.login.success")
    for event in logins:
        name = event.get("username")
        if isinstance(name, str) and 0 < len(name) <= MAX_USERNAME_LENGTH and name.isprintable():
            return name
    return None


def _describe(events: list[dict], username: str | None) -> tuple[str, str]:
    """The catalogue attack type and a detail line built from a template, never from raw input."""
    ids = {e.get("eventid") for e in events}
    who = f" as {username}" if username else ""
    if "cowrie.session.file_download" in ids:
        return "malware_dropper", f"file fetched after login{who}"
    if ids & COMMAND_EVENTS:
        return "ssh_bruteforce", f"login{who}, then commands were run"
    if ids & LOGIN_EVENTS:
        worked = "cowrie.login.success" in ids
        return "ssh_bruteforce", f"login succeeded{who}" if worked else f"login attempt{who}"
    return "port_scan", "connection with no login attempt"


def _sensor(session_id: str, lat: float, lng: float) -> Sensor:
    """A fictional sensor, stable for this session, that is not on top of the source."""
    start = int(hashlib.sha256(session_id.encode("utf-8")).hexdigest(), 16) % len(SENSORS)
    for step in range(len(SENSORS)):
        sensor = SENSORS[(start + step) % len(SENSORS)]
        if abs(sensor.lat - lat) > 1 or abs(sensor.lng - lng) > 1:
            return sensor
    return SENSORS[start]


def convert_sessions(sessions: dict[str, list[dict]]) -> tuple[list[AttackEvent], Counter]:
    """Turn {session id: events} into replay events sorted by start time."""
    started: list[tuple[datetime, str, list[dict]]] = []
    counts: Counter = Counter()
    for session_id, events in sessions.items():
        events = [e for e in events if isinstance(e, dict) and isinstance(e.get("timestamp"), str)]
        if not events:
            counts["skipped_no_events"] += 1
            continue
        try:
            begin = min(_parse_time(e["timestamp"]) for e in events)
        except ValueError:
            counts["skipped_bad_time"] += 1
            continue
        started.append((begin, session_id, events))
    started.sort(key=lambda item: item[0])

    converted: list[AttackEvent] = []
    for begin, session_id, events in started:
        place = _location(events)
        if place is None:
            counts["skipped_no_location"] += 1
            continue
        country, city, lat, lng = place
        username = _username(events)
        attack_type, detail = _describe(events, username)
        profile = ATTACK_TYPES[attack_type]
        sensor = _sensor(session_id, lat, lng)
        converted.append(
            AttackEvent(
                id=f"evt_{len(converted) + 1:06d}",
                ts=begin,
                original_ts=begin,
                attack_type=attack_type,
                label=profile.label,
                severity=profile.severity,
                port=ASSUMED_PORT,
                service=profile.service,
                detail=detail,
                username=username,
                mitre=Mitre(id=profile.mitre_id, name=profile.mitre_name),
                src=Source(country=country, city=city, lat=lat, lng=lng),
                dst=Target(name=sensor.name, lat=sensor.lat, lng=sensor.lng),
                simulated=False,
                source="replay",
                dataset=DATASET,
            )
        )
    counts["written"] = len(converted)
    return converted, counts


def convert(source: Path, destination: Path) -> Counter:
    size = unzipped_size(source)
    if size > MAX_UNZIPPED_BYTES:
        raise ConversionError(
            f"{source.name} is about {size // 1_000_000} MB once unzipped, and this tool holds a "
            f"whole day in memory (limit {MAX_UNZIPPED_BYTES // 1_000_000} MB). Pick a smaller day."
        )
    opener = gzip.open if source.suffix == ".gz" else open
    with opener(source, "rt", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ConversionError("Expected a JSON list of sessions, the CyberLab day file layout.")
    sessions: dict[str, list[dict]] = {}
    for item in data:
        if isinstance(item, dict):
            for session_id, events in item.items():
                if isinstance(events, list):
                    sessions.setdefault(session_id, []).extend(events)
    events, counts = convert_sessions(sessions)
    counts["sessions"] = len(sessions)
    with destination.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.model_dump_json() + "\n")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", type=Path, help="a CyberLab day file, .json or .json.gz")
    parser.add_argument("destination", type=Path, help="the replay file to write")
    args = parser.parse_args()
    try:
        counts = convert(args.source, args.destination)
    except (ConversionError, OSError, json.JSONDecodeError) as error:
        print(f"Could not convert {args.source}: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {counts['written']} events to {args.destination}. {dict(counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
