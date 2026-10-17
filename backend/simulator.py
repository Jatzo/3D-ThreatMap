"""Synthetic attack-event generator.

Produces realistic-looking (but entirely fake) attack events so the project runs
anywhere with no honeypot, API keys or network access. It is the default source;
backend/sources/ can replay a file of public data through the same AttackEvent model.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from .catalog import ATTACK_TYPES, SENSORS, SOURCES
from .models import AttackEvent, Mitre, Source, Target


class AttackSimulator:
    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._counter = 0
        self._type_keys = list(ATTACK_TYPES)
        self._type_weights = [ATTACK_TYPES[k].weight for k in self._type_keys]
        self._src_weights = [s.weight for s in SOURCES]

    def _random_ip(self) -> str:
        # 198.18.0.0/15 is reserved for network benchmarking (RFC 2544) and is never
        # routable on the public internet, so no real host is ever implied.
        rng = self._rng
        return f"198.{rng.choice((18, 19))}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

    def _jitter(self, lat: float, lng: float) -> tuple[float, float]:
        rng = self._rng
        lat = max(-90.0, min(90.0, lat + rng.uniform(-0.6, 0.6)))
        lng = ((lng + rng.uniform(-0.6, 0.6) + 180) % 360) - 180
        return round(lat, 4), round(lng, 4)

    def next_event(self, now: datetime | None = None) -> AttackEvent:
        rng = self._rng
        key = rng.choices(self._type_keys, self._type_weights)[0]
        profile = ATTACK_TYPES[key]
        src = rng.choices(SOURCES, self._src_weights)[0]
        candidates = [s for s in SENSORS if (s.lat, s.lng) != (src.lat, src.lng)]
        dst = rng.choice(candidates)

        username = rng.choice(profile.usernames) if profile.usernames else None
        detail = rng.choice(profile.details).format(username=username or "")
        lat, lng = self._jitter(src.lat, src.lng)

        self._counter += 1
        return AttackEvent(
            id=f"evt_{self._counter:06d}",
            ts=now or datetime.now(timezone.utc),
            attack_type=key,
            label=profile.label,
            severity=profile.severity,
            port=rng.choice(profile.ports),
            service=profile.service,
            detail=detail,
            username=username,
            mitre=Mitre(id=profile.mitre_id, name=profile.mitre_name),
            src=Source(
                ip=self._random_ip(), country=src.country, city=src.city, lat=lat, lng=lng
            ),
            dst=Target(name=dst.name, lat=dst.lat, lng=dst.lng),
        )

    async def stream(self, rate: float = 2.0) -> AsyncIterator[AttackEvent]:
        """Yield events forever with Poisson-distributed arrivals (`rate` events/sec)."""
        if rate <= 0:
            raise ValueError("rate must be positive")
        while True:
            yield self.next_event()
            await asyncio.sleep(self._rng.expovariate(rate))
