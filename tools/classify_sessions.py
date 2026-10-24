"""Classify sessions with the rules, and optionally with Claude, and attach the result to a replay.

    python -m tools.classify_sessions --sessions local/sessions.jsonl --key local/label_key.csv \
        --dry-run

The rules classifier is free and runs on every session. The model runs only on the sessions you
select (the labelled ones with --key, or the first N with --limit), only with --llm, and only
within --max-spend. Always do a --dry-run first: it prints the number of calls and the most they
can cost, and calls nothing. The key is read from ANTHROPIC_API_KEY or an `ant auth login`
profile in your own shell and is never stored here. Needs `pip install -r requirements-ai.txt`.

Outputs, all under local/ and never committed: verdicts.jsonl (with the model's free-text note),
and with --enrich-replay and --enriched-out a copy of a replay file whose events carry the
verdicts (without the note) for the page to show.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from backend.classify.llm import DEFAULT_MAX_SPEND, DEFAULT_MODEL, LlmClassifier, SpendCapReached
from backend.classify.rules import classify_rules
from backend.classify.session import SessionRecord, read_records
from backend.models import Analysis, AttackEvent


def select(
    records: list[SessionRecord], key: Path | None, limit: int | None
) -> list[SessionRecord]:
    if key:
        with key.open(encoding="utf-8", newline="") as handle:
            wanted = {row["event_id"] for row in csv.DictReader(handle)}
        records = [r for r in records if r.event_id in wanted]
    return records[:limit] if limit else records


def enrich(replay: Path, destination: Path, verdicts: dict[str, dict]) -> int:
    """Copy a replay file, adding the verdicts (never the model's note) to the events they cover."""
    done = 0
    with replay.open(encoding="utf-8") as source, destination.open("w", encoding="utf-8") as out:
        for line in source:
            if not line.strip():
                continue
            event = AttackEvent.model_validate_json(line)
            found = verdicts.get(event.id)
            if found:
                llm = found.get("llm")
                event = event.model_copy(
                    update={
                        "analysis": Analysis(
                            rules=found["rules"].model_copy(update={"note": None}),
                            llm=llm.model_copy(update={"note": None}) if llm else None,
                        )
                    }
                )
                done += 1
            out.write(event.model_dump_json() + "\n")
    return done


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("local/verdicts.jsonl"))
    parser.add_argument("--key", type=Path, help="run the model only on the sessions in this key")
    parser.add_argument("--limit", type=int, help="run the model only on the first N sessions")
    parser.add_argument("--llm", action="store_true", help="also ask the model (spends money)")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--max-spend", type=float, default=DEFAULT_MAX_SPEND, help="dollars, a hard cap"
    )
    parser.add_argument("--cache", type=Path, default=Path("local/llm_cache.jsonl"))
    parser.add_argument("--dry-run", action="store_true", help="print the cost bound and stop")
    parser.add_argument("--enrich-replay", type=Path)
    parser.add_argument("--enriched-out", type=Path)
    args = parser.parse_args()

    if args.llm and not (args.key or args.limit):
        print("Choose which sessions the model sees, with --key or --limit.", file=sys.stderr)
        return 1
    try:
        records = read_records(args.sessions)
        chosen = select(records, args.key, args.limit)
    except (OSError, KeyError, ValueError) as error:
        print(f"Cannot read the sessions or the key: {error}", file=sys.stderr)
        return 1
    verdicts = {r.event_id: {"rules": classify_rules(r), "llm": None} for r in records}

    if args.llm or args.dry_run:
        classifier = LlmClassifier(None, args.model, args.max_spend, args.cache)
        calls, worst = classifier.estimate(chosen)
        print(
            f"{len(chosen)} sessions selected, {calls} need a call (the rest are cached). "
            f"Worst case ${worst:.2f} at list price for {args.model}; cap ${args.max_spend:.2f}."
        )
        if args.dry_run:
            return 0
        if worst > args.max_spend:
            print("The worst case is over the cap, so some calls may be skipped.", file=sys.stderr)
        try:
            import anthropic

            # No retries: a retried request that timed out can be billed twice, and the spend
            # cap only counts answers it saw. A failed call becomes an abstention, and a rerun
            # tries it again while the cache keeps the finished ones free.
            client = anthropic.Anthropic(max_retries=0)
        except ImportError:
            print("Install the package first: pip install -r requirements-ai.txt", file=sys.stderr)
            return 1
        classifier = LlmClassifier(client, args.model, args.max_spend, args.cache)
        try:
            for record in chosen:
                verdicts[record.event_id]["llm"] = classifier.classify(record)
        except SpendCapReached as stop:
            print(stop, file=sys.stderr)
        print(
            f"Calls: {classifier.calls}. Cache hits: {classifier.cache_hits}. "
            f"Spent: ${classifier.spent:.2f}."
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for event_id, found in verdicts.items():
            handle.write(
                json.dumps(
                    {
                        "event_id": event_id,
                        "rules": found["rules"].model_dump(mode="json"),
                        "llm": found["llm"].model_dump(mode="json") if found["llm"] else None,
                    }
                )
                + "\n"
            )
    print(f"Wrote {len(verdicts)} verdicts to {args.out}.")

    if args.enrich_replay and args.enriched_out:
        done = enrich(args.enrich_replay, args.enriched_out, verdicts)
        print(f"Added analysis to {done} events in {args.enriched_out}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
