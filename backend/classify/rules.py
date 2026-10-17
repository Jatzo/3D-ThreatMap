"""The rules classifier: the labelling guide written as code.

It is the baseline the model is measured against. It reads only what `evidence()` shows, and the
first class in the taxonomy whose test is met wins, which is the tie-break in the guide.
"""

from __future__ import annotations

import re

from ..models import Mitre, Verdict
from .session import SessionRecord
from .taxonomy import BY_KEY

FETCH_COMMAND = re.compile(r"\b(wget|curl|tftp|ftpget)\b", re.I)


def count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"


def verdict_for(key: str, reasons: list[str], model: str | None = None) -> Verdict:
    """A verdict for a taxonomy class, with the technique taken from the table."""
    chosen = BY_KEY[key]
    mitre = None
    if chosen.technique_id:
        mitre = Mitre(id=chosen.technique_id, name=chosen.technique_name)
    return Verdict(label=key, mitre=mitre, reasons=reasons, model=model)


def classify_rules(record: SessionRecord) -> Verdict:
    if record.downloads or any(FETCH_COMMAND.search(command) for command in record.commands):
        reasons = [f"{count(len(record.downloads), 'file download')} recorded"]
        if any(FETCH_COMMAND.search(command) for command in record.commands):
            reasons.append("a command tries to fetch a file")
        return verdict_for("malware_delivery", reasons)
    if record.commands_total > 0:
        reasons = [f"{count(record.commands_total, 'command')} ran after login"]
        return verdict_for("post_login_commands", reasons)
    if record.tunnel_requests > 0:
        reasons = [f"{count(record.tunnel_requests, 'port-forward request')} made"]
        return verdict_for("proxy_tunnelling", reasons)
    if record.login_attempts > 0:
        reasons = [f"{count(record.login_attempts, 'login attempt')} made"]
        return verdict_for("credential_guessing", reasons)
    return verdict_for("scan_probe", ["no login attempt and no port forwarding"])
