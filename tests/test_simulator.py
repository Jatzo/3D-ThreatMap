import asyncio
import ipaddress
import re

import pytest

from backend.catalog import ATTACK_TYPES, SENSORS
from backend.models import AttackEvent
from backend.simulator import AttackSimulator

BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")


def make_events(n: int, seed: int = 42) -> list[AttackEvent]:
    sim = AttackSimulator(seed=seed)
    return [sim.next_event() for _ in range(n)]


def test_events_are_valid_models():
    for ev in make_events(300):
        AttackEvent.model_validate(ev.model_dump())
        assert ev.simulated is True


def test_same_seed_gives_same_sequence():
    a = [(e.attack_type, e.src.city, e.dst.name, e.port) for e in make_events(50, seed=7)]
    b = [(e.attack_type, e.src.city, e.dst.name, e.port) for e in make_events(50, seed=7)]
    assert a == b


def test_ids_are_unique_and_sequential():
    ids = [e.id for e in make_events(100)]
    assert len(set(ids)) == 100
    assert ids[0] == "evt_000001"


def test_source_ips_are_never_routable():
    for ev in make_events(300):
        assert ipaddress.ip_address(ev.src.ip) in BENCHMARK_NET


def test_arcs_never_have_zero_length():
    # Source coordinates are jittered by at most 0.6 degrees per axis, and the simulator
    # skips any sensor that shares coordinates with the source city, so every arc must
    # span clearly more than the jitter.
    sensor_coords = {(s.lat, s.lng) for s in SENSORS}
    for ev in make_events(1000):
        assert (ev.dst.lat, ev.dst.lng) in sensor_coords
        assert abs(ev.src.lat - ev.dst.lat) > 1 or abs(ev.src.lng - ev.dst.lng) > 1


def test_mix_covers_every_attack_type():
    seen = {e.attack_type for e in make_events(1000)}
    assert seen == set(ATTACK_TYPES)


def test_mitre_ids_look_valid_and_ports_match_profile():
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for ev in make_events(300):
        profile = ATTACK_TYPES[ev.attack_type]
        assert pattern.match(ev.mitre.id)
        assert ev.port in profile.ports
        assert ev.label == profile.label


def test_usernames_only_on_credential_attacks():
    for ev in make_events(300):
        if ATTACK_TYPES[ev.attack_type].usernames:
            assert ev.username in ATTACK_TYPES[ev.attack_type].usernames
        else:
            assert ev.username is None


def test_stream_yields_events_and_rejects_bad_rate():
    async def take(n: int) -> list[AttackEvent]:
        out = []
        async for ev in AttackSimulator(seed=1).stream(rate=500):
            out.append(ev)
            if len(out) == n:
                break
        return out

    assert len(asyncio.run(take(5))) == 5

    async def bad() -> None:
        async for _ in AttackSimulator().stream(rate=0):
            pass

    with pytest.raises(ValueError):
        asyncio.run(bad())
