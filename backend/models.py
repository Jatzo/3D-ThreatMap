"""Pydantic models describing the events streamed to the frontend."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator

from .catalog import ATTACK_TYPES
from .classify.taxonomy import ABSTAIN, KEYS


class Mitre(BaseModel):
    id: str
    name: str


class Verdict(BaseModel):
    """One classifier's answer for one session."""

    label: str
    mitre: Mitre | None = None
    # Fixed sentences from the rules classifier. The model's verdict carries none.
    reasons: list[str] = Field(default_factory=list, max_length=6)
    model: str | None = None
    # Free text from the model. It can quote the session, so it stays in local reports.
    note: str | None = None

    @field_validator("label")
    @classmethod
    def _known_label(cls, value: str) -> str:
        if value != ABSTAIN and value not in KEYS:
            raise ValueError(f"unknown session class {value!r}")
        return value

    @field_validator("reasons")
    @classmethod
    def _short_reasons(cls, value: list[str]) -> list[str]:
        if any(len(reason) > 160 for reason in value):
            raise ValueError("a reason is longer than 160 characters")
        return value


class Analysis(BaseModel):
    rules: Verdict
    llm: Verdict | None = None

    @model_validator(mode="after")
    def _no_free_text(self) -> Analysis:
        if any(v is not None and v.note is not None for v in (self.rules, self.llm)):
            raise ValueError("free text from the model must not travel with an event")
        return self


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
    # What the classifiers made of the session behind this event, when that has been run.
    analysis: Analysis | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> AttackEvent:
        if self.attack_type not in ATTACK_TYPES:
            raise ValueError(f"unknown attack_type {self.attack_type!r}")
        if self.dataset is not None and self.simulated:
            raise ValueError("an event from a dataset cannot be marked simulated")
        return self
