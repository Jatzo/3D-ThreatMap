"""The session classes, in the order that settles a tie, each with its ATT&CK technique.

One table feeds the rules classifier, the model's prompt and answer format, the labelling guide,
the evaluation and the page. Most sessions show more than one behaviour, so the first class in
CLASSES whose test is met wins: a session that downloaded a file and also tried passwords is
malware delivery. Technique IDs were checked against attack.mitre.org on 17 October 2026.
"""

from __future__ import annotations

from dataclasses import dataclass

# A verdict that is not a class: the model declined, ran out of room or gave an unusable answer.
# It is counted in the evaluation as a miss and is kept apart from "other".
ABSTAIN = "abstain"


@dataclass(frozen=True)
class SessionClass:
    key: str
    name: str
    technique_id: str | None
    technique_name: str | None
    meaning: str


CLASSES: tuple[SessionClass, ...] = (
    SessionClass(
        "malware_delivery",
        "Malware delivery",
        "T1105",
        "Ingress Tool Transfer",
        "A file was downloaded in the session, or a command tries to fetch one "
        "(wget, curl, tftp, ftpget).",
    ),
    SessionClass(
        "post_login_commands",
        "Commands after login",
        "T1059.004",
        "Unix Shell",
        "A login worked and commands were run, with no file download or fetch command.",
    ),
    SessionClass(
        "proxy_tunnelling",
        "Port forwarding",
        "T1572",
        "Protocol Tunneling",
        "The session asked the honeypot to forward network connections (SSH port forwarding), "
        "with none of the behaviour above.",
    ),
    SessionClass(
        "credential_guessing",
        "Credential guessing",
        "T1110.001",
        "Password Guessing",
        "One or more logins were tried, with none of the behaviour above.",
    ),
    SessionClass(
        "scan_probe",
        "Scan or probe",
        "T1046",
        "Network Service Discovery",
        "A connection with no login attempt and no port forwarding.",
    ),
    SessionClass(
        "other",
        "Other",
        None,
        None,
        "None of the above fits. Rules never give this; a person or the model may.",
    ),
)

KEYS: tuple[str, ...] = tuple(c.key for c in CLASSES)
BY_KEY: dict[str, SessionClass] = {c.key: c for c in CLASSES}

# The colour category the replay events use on the page (the keys of the page's catalogue).
DISPLAY_TYPE: dict[str, str] = {
    "malware_delivery": "malware_dropper",
    "post_login_commands": "ssh_bruteforce",
    "proxy_tunnelling": "ssh_bruteforce",
    "credential_guessing": "ssh_bruteforce",
    "scan_probe": "port_scan",
    "other": "port_scan",
}


def guide_text() -> str:
    """The labelling guide, written from the table so it cannot drift from the code."""
    lines = [
        "# Labelling guide",
        "",
        "For each session, pick the one class below that best says what the session was doing.",
        "When more than one class fits, choose the earliest one in this list.",
        "",
    ]
    for number, c in enumerate(CLASSES, start=1):
        technique = f" ({c.technique_id}, {c.technique_name})" if c.technique_id else ""
        lines.append(f"{number}. `{c.key}`: {c.name}{technique}. {c.meaning}")
    lines += [
        "",
        "Write the class key in the `label` column. Leave `label` empty for a session you cannot",
        "judge, and say why in `notes`. Passwords are not shown. URLs and addresses are written",
        "with brackets, like `hxxp://203[.]0[.]113[.]9/x`, so they cannot be clicked by mistake.",
    ]
    return "\n".join(lines) + "\n"
