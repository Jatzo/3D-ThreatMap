"""Score the classifiers against the labels you wrote by hand.

    python -m tools.evaluate --labels local/label_sheet.csv --key local/label_key.csv \
        --strata local/label_strata.json --verdicts local/verdicts.jsonl

The sample was stratified, so a plain accuracy over the sheet over-counts the rare strata. The
report therefore gives the sample accuracy, an accuracy re-weighted to the real size of each
stratum, and the result inside every stratum. It gives no confidence interval: with a stratified
sample of this size an honest one needs more than a formula, so read the per-stratum counts
instead. A verdict of "abstain" counts as a miss.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from backend.classify.taxonomy import ABSTAIN, KEYS


def _ratio(top: int, bottom: int) -> float | None:
    return top / bottom if bottom else None


def score(
    truth: list[str],
    predicted: list[str],
    strata: list[str],
    sizes: dict[str, int],
    labelled: dict[str, int],
) -> dict:
    """Accuracy (plain and re-weighted), per-stratum results, per-class scores, confusion."""
    hits = [t == p for t, p in zip(truth, predicted, strict=True)]
    weights = [sizes[s] / labelled[s] for s in strata]
    per_stratum: dict[str, list[int]] = {}
    for stratum, hit in zip(strata, hits, strict=True):
        got = per_stratum.setdefault(stratum, [0, 0])
        got[0] += hit
        got[1] += 1
    classes: dict[str, dict] = {}
    for key in KEYS:
        right = sum(1 for t, p in zip(truth, predicted, strict=True) if t == p == key)
        said = predicted.count(key)
        real = truth.count(key)
        precision, recall = _ratio(right, said), _ratio(right, real)
        both = None
        if precision is not None and recall is not None and precision + recall > 0:
            both = 2 * precision * recall / (precision + recall)
        classes[key] = {"precision": precision, "recall": recall, "f1": both, "support": real}
    with_support = [c for c in classes.values() if c["support"] > 0]
    macro_f1 = None
    if with_support:
        macro_f1 = sum(c["f1"] or 0.0 for c in with_support) / len(with_support)
    won = sum(w for w, h in zip(weights, hits, strict=True) if h)
    return {
        "n": len(truth),
        "accuracy": _ratio(sum(hits), len(hits)),
        "weighted_accuracy": _ratio(won, sum(weights)),
        "per_stratum": {name: tuple(got) for name, got in per_stratum.items()},
        "classes": classes,
        "macro_f1": macro_f1,
        "abstentions": predicted.count(ABSTAIN),
        "confusion": Counter(zip(truth, predicted, strict=True)),
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def render(name: str, result: dict) -> str:
    lines = [
        f"## {name}",
        "",
        f"Labelled sessions: {result['n']}. Abstentions: {result['abstentions']}.",
        f"Accuracy on the sample: {_pct(result['accuracy'])}. "
        f"Re-weighted to the real strata: {_pct(result['weighted_accuracy'])}. "
        f"Macro F1 over classes that appear in the labels: {_pct(result['macro_f1'])}.",
        "",
        "| Stratum | Right | Of |",
        "|---|---|---|",
    ]
    lines += [f"| {s} | {right} | {n} |" for s, (right, n) in sorted(result["per_stratum"].items())]
    lines += ["", "| Class | Precision | Recall | F1 | Labelled |", "|---|---|---|---|---|"]
    for key, c in result["classes"].items():
        cells = [_pct(c["precision"]), _pct(c["recall"]), _pct(c["f1"]), str(c["support"])]
        lines.append(f"| {key} | " + " | ".join(cells) + " |")
    lines += ["", "Confusion (label by you, then what the classifier said):", ""]
    lines += [f"- {t} -> {p}: {n}" for (t, p), n in sorted(result["confusion"].items())]
    return "\n".join(lines) + "\n"


def load_labels(sheet: Path, key: Path) -> list[dict]:
    """Labelled rows only, as {sheet_id, event_id, stratum, label}. Bad labels stop the run."""
    with key.open(encoding="utf-8", newline="") as handle:
        keyed = {row["sheet_id"]: row for row in csv.DictReader(handle)}
    rows, bad = [], []
    with sheet.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            label = (row.get("label") or "").strip()
            if not label:
                continue
            if label not in KEYS:
                bad.append(f"{row['sheet_id']}: {label!r}")
                continue
            rows.append({**keyed[row["sheet_id"]], "label": label})
    if bad:
        raise ValueError("These labels are not class keys: " + ", ".join(bad))
    if not rows:
        raise ValueError(f"No labels found in {sheet}. Fill in the label column first.")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--labels", type=Path, required=True, help="the sheet you labelled")
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--strata", type=Path, required=True)
    parser.add_argument("--verdicts", type=Path, required=True)
    parser.add_argument("--out", type=Path, help="also write the report here")
    args = parser.parse_args()
    try:
        rows = load_labels(args.labels, args.key)
        info = json.loads(args.strata.read_text(encoding="utf-8"))
        verdicts = {}
        with args.verdicts.open(encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                verdicts[record["event_id"]] = record
    except (ValueError, OSError, KeyError) as error:
        print(f"Cannot evaluate: {error}", file=sys.stderr)
        return 1
    report = [f"# Evaluation on {len(rows)} labelled sessions\n"]
    for name in ("rules", "llm"):
        have = [r for r in rows if verdicts.get(r["event_id"], {}).get(name)]
        if len(have) < len(rows):
            missing = len(rows) - len(have)
            report.append(
                f"## {name}\n\nNot scored: {missing} labelled sessions have no verdict yet. "
                "Run tools.classify_sessions first.\n"
            )
            continue
        # Weights use the sessions actually labelled in each stratum, not the number sampled.
        result = score(
            [r["label"] for r in have],
            [verdicts[r["event_id"]][name]["label"] for r in have],
            [r["stratum"] for r in have],
            info["sizes"],
            Counter(r["stratum"] for r in have),
        )
        report.append(render(name, result))
    text = "\n".join(report)
    print(text)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
