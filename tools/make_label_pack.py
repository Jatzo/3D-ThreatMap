"""Build the labelling pack: a sheet of sessions to label by hand, and what is needed to score it.

    python -m tools.make_label_pack --sessions local/sessions.jsonl

Writes four files into local/ (never committed):

  label_sheet.csv      the sessions to label, in a shuffled order, with empty label and notes
  label_key.csv        sheet id, event id and stratum, kept apart from the sheet
  label_strata.json    how many sessions each stratum has and how many were sampled
  labelling_guide.md   the classes and the tie-break, written from the taxonomy

The sample is stratified on what the session did (raw counts), not on any classifier's answer, and
every stratum with 12 sessions or fewer is taken whole. The sheet shows exactly the evidence the
model is shown and no classifier output. It is not blind in the strict sense: the same person
wrote the guide, the rules and the labels, so agreement with the rules is partly circular.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

from backend.classify.session import SessionRecord, evidence, read_records
from backend.classify.taxonomy import guide_text

STRATA = ("download", "commands", "tunnelling", "login_only", "connect_only")
TAKE_WHOLE_UP_TO = 12


def stratum(record: SessionRecord) -> str:
    """What the session did, from its raw counts alone."""
    if record.downloads:
        return "download"
    if record.commands_total > 0:
        return "commands"
    if record.tunnel_requests > 0:
        return "tunnelling"
    if record.login_attempts > 0:
        return "login_only"
    return "connect_only"


def allocate(sizes: dict[str, int], total: int) -> dict[str, int]:
    """How many sessions to take from each stratum: small ones whole, the rest equally."""
    whole = {name: n for name, n in sizes.items() if 0 < n <= TAKE_WHOLE_UP_TO}
    left = total - sum(whole.values())
    if left < 0:
        raise ValueError("The small strata alone are bigger than the sample size.")
    taken = dict(whole)
    big = sorted((name for name, n in sizes.items() if n > TAKE_WHOLE_UP_TO), key=sizes.get)
    for position, name in enumerate(big):
        taken[name] = min(sizes[name], left // (len(big) - position))
        left -= taken[name]
    return taken


def build_pack(records: list[SessionRecord], size: int, seed: int) -> dict:
    groups: dict[str, list[SessionRecord]] = {name: [] for name in STRATA}
    for record in records:
        groups[stratum(record)].append(record)
    sizes = {name: len(group) for name, group in groups.items()}
    taken = allocate(sizes, size)
    rng = random.Random(seed)
    chosen = [(name, r) for name in STRATA for r in rng.sample(groups[name], taken.get(name, 0))]
    rng.shuffle(chosen)
    return {"sizes": sizes, "sampled": taken, "chosen": chosen, "seed": seed}


def write_pack(pack: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    chosen = pack["chosen"]
    columns = list(evidence(chosen[0][1])) if chosen else []
    with (out / "label_sheet.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sheet_id", *columns, "label", "notes"])
        for number, (_, record) in enumerate(chosen, start=1):
            writer.writerow([f"S{number:02d}", *evidence(record).values(), "", ""])
    with (out / "label_key.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sheet_id", "event_id", "stratum"])
        for number, (name, record) in enumerate(chosen, start=1):
            writer.writerow([f"S{number:02d}", record.event_id, name])
    summary = {k: pack[k] for k in ("sizes", "sampled", "seed")}
    (out / "label_strata.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "labelling_guide.md").write_text(guide_text(), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("local"))
    parser.add_argument("--size", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    pack = build_pack(read_records(args.sessions), args.size, args.seed)
    write_pack(pack, args.out)
    print(f"Strata sizes: {pack['sizes']}. Sampled: {pack['sampled']}. Files are in {args.out}/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
