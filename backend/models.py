"""Pydantic models describing the events streamed to the frontend."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Mitre(BaseModel):
    id: str
    name: str


class Source(BaseModel):
    ip: str
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
