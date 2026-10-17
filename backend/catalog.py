"""Static reference data for the attack simulator.

Everything here is illustrative. Source weights are loosely inspired by the broad
geographic spread public honeypot reports tend to show; they are not measurements.
If you change the attack types, keep frontend/index.html in sync (a test checks it).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceCity:
    country: str
    city: str
    lat: float
    lng: float
    weight: int


@dataclass(frozen=True)
class Sensor:
    name: str
    lat: float
    lng: float


@dataclass(frozen=True)
class AttackProfile:
    label: str
    ports: tuple[int, ...]
    service: str
    mitre_id: str
    mitre_name: str
    severity: int
    weight: int
    details: tuple[str, ...]
    usernames: tuple[str, ...] = ()


SOURCES: list[SourceCity] = [
    SourceCity(*row)
    for row in (
        ("China", "Beijing", 39.90, 116.41, 16),
        ("China", "Shanghai", 31.23, 121.47, 8),
        ("United States", "Ashburn", 39.04, -77.49, 10),
        ("United States", "Dallas", 32.78, -96.80, 5),
        ("Russia", "Moscow", 55.76, 37.62, 9),
        ("India", "Mumbai", 19.08, 72.88, 6),
        ("Brazil", "São Paulo", -23.55, -46.63, 6),
        ("Germany", "Frankfurt", 50.11, 8.68, 4),
        ("Netherlands", "Amsterdam", 52.37, 4.90, 5),
        ("Vietnam", "Hanoi", 21.03, 105.85, 5),
        ("South Korea", "Seoul", 37.57, 126.98, 5),
        ("Indonesia", "Jakarta", -6.21, 106.85, 4),
        ("Iran", "Tehran", 35.69, 51.39, 3),
        ("Ukraine", "Kyiv", 50.45, 30.52, 3),
        ("Turkey", "Istanbul", 41.01, 28.98, 3),
        ("Romania", "Bucharest", 44.43, 26.10, 3),
        ("Egypt", "Cairo", 30.04, 31.24, 2),
        ("Nigeria", "Lagos", 6.52, 3.38, 2),
        ("South Africa", "Johannesburg", -26.20, 28.05, 2),
        ("Argentina", "Buenos Aires", -34.60, -58.38, 2),
        ("Mexico", "Mexico City", 19.43, -99.13, 2),
        ("Thailand", "Bangkok", 13.76, 100.50, 3),
        ("Pakistan", "Karachi", 24.86, 67.01, 2),
        ("Taiwan", "Taipei", 25.03, 121.57, 3),
        ("Singapore", "Singapore", 1.35, 103.82, 3),
        ("France", "Paris", 48.86, 2.35, 2),
        ("United Kingdom", "London", 51.51, -0.13, 2),
        ("Australia", "Sydney", -33.87, 151.21, 2),
        ("Japan", "Tokyo", 35.68, 139.69, 2),
        ("Poland", "Warsaw", 52.23, 21.01, 2),
    )
]

# Fictional sensor locations (the "victims" the arcs point at).
SENSORS: list[Sensor] = [
    Sensor(*row)
    for row in (
        ("London", 51.51, -0.13),
        ("Frankfurt", 50.11, 8.68),
        ("N. Virginia", 39.04, -77.49),
        ("Oregon", 45.52, -122.68),
        ("Singapore", 1.35, 103.82),
        ("Sydney", -33.87, 151.21),
        ("São Paulo", -23.55, -46.63),
    )
]

ATTACK_TYPES: dict[str, AttackProfile] = {
    "ssh_bruteforce": AttackProfile(
        label="SSH brute force",
        ports=(22, 2222),
        service="ssh",
        mitre_id="T1110.001",
        mitre_name="Password Guessing",
        severity=2,
        weight=30,
        details=("login attempt as {username}", "dictionary attack as {username}"),
        usernames=("root", "admin", "ubuntu", "pi", "user", "test", "oracle", "git", "deploy"),
    ),
    "telnet_botnet": AttackProfile(
        label="Telnet botnet",
        ports=(23, 2323),
        service="telnet",
        mitre_id="T1110.003",
        mitre_name="Password Spraying",
        severity=3,
        weight=18,
        details=("default-credential spray as {username}", "IoT login sweep as {username}"),
        usernames=("root", "admin", "support", "default", "supervisor", "guest"),
    ),
    "rdp_bruteforce": AttackProfile(
        label="RDP brute force",
        ports=(3389,),
        service="rdp",
        mitre_id="T1110.001",
        mitre_name="Password Guessing",
        severity=3,
        weight=10,
        details=("RDP login attempt as {username}", "NLA credential guess as {username}"),
        usernames=("administrator", "admin", "user", "guest", "scanner"),
    ),
    "port_scan": AttackProfile(
        label="Port scan",
        ports=(21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5900, 8080),
        service="tcp",
        mitre_id="T1046",
        mitre_name="Network Service Discovery",
        severity=1,
        weight=25,
        details=("SYN sweep", "service banner grab", "wide subnet probe"),
    ),
    "web_exploit": AttackProfile(
        label="Web exploit",
        ports=(80, 443, 8080, 8443),
        service="http",
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        severity=4,
        weight=12,
        details=(
            "/.env probe",
            "JNDI lookup attempt",
            "path traversal attempt",
            "admin panel probe",
            "SQL injection probe",
        ),
    ),
    "malware_dropper": AttackProfile(
        label="Malware dropper",
        ports=(22, 23, 2222),
        service="shell",
        mitre_id="T1105",
        mitre_name="Ingress Tool Transfer",
        severity=5,
        weight=5,
        details=(
            "wget-and-run dropper script",
            "cryptominer fetch",
            "Mirai-style binary fetch",
        ),
    ),
}
