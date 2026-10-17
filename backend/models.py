"""Pydantic models describing the events streamed to the frontend."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from .catalog import ATTACK_TYPES


class Mitre(BaseModel):
    id: str
    name: str


class Source(BaseModel):
    # None when the data source does not give an address. Replayed public data
    # carries pseudonyms instead of addresses, and those never leave the server.
    ip: str | None = None
    country: str
    city: str
    lat: float = Field(ge=-90, le=90)
    lng: float = Field(ge=-180, le=180)


class Target(BaseModel):
    name: str
    lat: float = Field(ge=-90, le=90)
    lng: float = Field(ge=-180, le=180)


class AttackEvent(BaseModel):
    id: str
    ts: datetime
    attack_type: str
    label: str
    severity: int = Field(ge=1, le=5)
    port: int = Field(ge=1, le=65535)
    service: str
    detail: str
    username: str | None = None
    mitre: Mitre
    src: Source
    dst: Target
    simulated: bool = True
    source: str = "simulator"
    # Set only for events that come from a published dataset, with the credit to show.
    dataset: str | None = None
    # When the event happened in the original data, for replayed events.
    original_ts: datetime | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> AttackEvent:
        if self.attack_type not in ATTACK_TYPES:
            raise ValueError(f"unknown attack_type {self.attack_type!r}")
        if self.dataset is not None and self.simulated:
            raise ValueError("an event from a dataset cannot be marked simulated")
        return self
