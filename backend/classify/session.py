"""What is known about one honeypot session, cleaned so it is safe to store, show and send.

A session record is built from raw honeypot events by tools/convert_cyberlab.py and lives only in
local files. It never holds a password. Text that came from an attacker is stripped of control
characters and angle brackets, URLs and addresses are written with brackets so they cannot be
clicked, and a command that may carry a credential is replaced by a placeholder.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

MAX_USERNAMES = 10
MAX_COMMANDS = 20
MAX_DOWNLOADS = 5
TEXT_LIMIT = 200
USERNAME_LIMIT = 32
CLIENT_LIMIT = 64

WITHHELD = "[command withheld: may contain a credential]"
# Words that tend to sit next to a password, "echo user:secret" which feeds chpasswd, and the
# password options of curl.
_CREDENTIAL = re.compile(
    r"passwd|password|sshpass|secret|token|\becho\s+['\"]?\w+:\S+|\bcurl\b[^;|&]*\s(?:-u|--user)\b",
    re.I,
)
# user:password@ inside a URL, which wget and curl accept.
_URL_CREDENTIALS = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s@]*@", re.I)
_BRACKETS = str.maketrans({"<": " ", ">": " "})
_DOT_BETWEEN_WORD_CHARS = re.compile(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])")
_SCHEME = re.compile(r"\b(http|ftp)(s?)://", re.I)


def printable(value: object) -> str | None:
    """The text with control characters and angle brackets removed, or None if nothing is left."""
    if not isinstance(value, str):
        return None
    text = value.translate(_BRACKETS).replace("\n", " ").replace("\t", " ")
    text = "".join(char for char in text if char.isprintable()).strip()
    return text or None


def _hide_scheme(match: re.Match[str]) -> str:
    scheme = "hxxp" if match.group(1).lower() == "http" else "fxp"
    return f"{scheme}{match.group(2)}://"


def defang(text: str) -> str:
    """Write URLs and addresses so they cannot be clicked: hxxp://203[.]0[.]113[.]9/x."""
    return _DOT_BETWEEN_WORD_CHARS.sub("[.]", _SCHEME.sub(_hide_scheme, text))


def safe_text(value: object, limit: int = TEXT_LIMIT) -> str | None:
    text = printable(value)
    if not text:
        return None
    return defang(_URL_CREDENTIALS.sub(r"\1[credentials removed]@", text))[:limit]


def safe_command(value: object) -> str | None:
    text = printable(value)
    if text is None:
        return None
    return WITHHELD if _CREDENTIAL.search(text) else safe_text(text)


def safe_username(value: object) -> str | None:
    """A username as typed, or None if it holds control characters or is too long to be one."""
    text = printable(value)
    if text is None or len(text) > USERNAME_LIMIT or text != value:
        return None
    return text


class SessionRecord(BaseModel):
    event_id: str
    started: datetime
    country: str
    city: str
    login_attempts: int = Field(ge=0)
    logins_succeeded: int = Field(ge=0)
    usernames: list[str] = Field(default_factory=list, max_length=MAX_USERNAMES)
    commands: list[str] = Field(default_factory=list, max_length=MAX_COMMANDS)
    commands_total: int = Field(default=0, ge=0)
    downloads: list[str] = Field(default_factory=list, max_length=MAX_DOWNLOADS)
    tunnel_requests: int = Field(ge=0)
    duration_seconds: float | None = None
    client_version: str | None = None


def read_records(path: Path) -> list[SessionRecord]:
    with path.open(encoding="utf-8") as handle:
        return [SessionRecord.model_validate_json(line) for line in handle if line.strip()]


def evidence(record: SessionRecord) -> dict[str, str]:
    """What a person labelling the session, and the model, are shown. Nothing else.

    Place and time are left out on purpose: they say nothing about what the session did.
    """
    commands = " ; ".join(record.commands) or "none"
    if record.commands_total > len(record.commands):
        commands += f" (first {len(record.commands)} of {record.commands_total})"
    seconds = "unknown" if record.duration_seconds is None else f"{record.duration_seconds:.0f}"
    shown = {
        "login attempts": f"{record.login_attempts} ({record.logins_succeeded} succeeded)",
        "usernames tried": ", ".join(record.usernames) or "none",
        "commands run": commands,
        "files downloaded": ", ".join(record.downloads) or "none",
        "port-forward requests": str(record.tunnel_requests),
        "session length in seconds": seconds,
        "client software": record.client_version or "unknown",
    }
    # A record read back from a file could hold anything, so the brackets are stripped again here.
    return {name: value.translate(_BRACKETS) for name, value in shown.items()}
