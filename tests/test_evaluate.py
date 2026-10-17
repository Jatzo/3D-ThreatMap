import csv
import json
import sys

import pytest

from backend.classify.taxonomy import ABSTAIN
from tools import evaluate
from tools.evaluate import load_labels, score

SCAN, GUESS = "scan_probe", "credential_guessing"


def small_example():
    return score(
        truth=[SCAN, SCAN, GUESS, GUESS],
        predicted=[SCAN, GUESS, GUESS, GUESS],
        strata=["s1", "s1", "s2", "s2"],
        sizes={"s1": 100, "s2": 10},
        sampled={"s1": 2, "s2": 2},
    )


def test_accuracy_and_the_reweighted_accuracy_match_a_hand_count():
    result = small_example()
    assert result["accuracy"] == 0.75
    # Each s1 row stands for 50 sessions and each s2 row for 5: (50 + 5 + 5) / 110.
    assert result["weighted_accuracy"] == pytest.approx(60 / 110)
    assert result["per_stratum"] == {"s1": (1, 2), "s2": (2, 2)}


def test_precision_recall_and_f1_match_a_hand_count():
    classes = small_example()["classes"]
    assert classes[SCAN]["precision"] == 1.0
    assert classes[SCAN]["recall"] == 0.5
    assert classes[SCAN]["f1"] == pytest.approx(2 / 3)
    assert classes[GUESS]["precision"] == pytest.approx(2 / 3)
    assert classes[GUESS]["recall"] == 1.0
    assert classes[GUESS]["f1"] == pytest.approx(0.8)
    assert small_example()["macro_f1"] == pytest.approx((2 / 3 + 0.8) / 2)


def test_a_class_nobody_labelled_does_not_pull_the_macro_score_down():
    classes = small_example()["classes"]
    assert classes["malware_delivery"]["support"] == 0
    assert classes["malware_delivery"]["recall"] is None


def test_an_abstention_counts_as_a_miss_and_is_counted():
    result = score([SCAN, GUESS], [SCAN, ABSTAIN], ["s", "s"], {"s": 2}, {"s": 2})
    assert result["accuracy"] == 0.5
    assert result["abstentions"] == 1
    assert result["confusion"][(GUESS, ABSTAIN)] == 1


def write_files(tmp_path, labels):
    sheet = tmp_path / "sheet.csv"
    with sheet.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sheet_id", "commands run", "label", "notes"])
        for number, label in enumerate(labels, start=1):
            writer.writerow([f"S{number:02d}", "none", label, ""])
    key = tmp_path / "key.csv"
    with key.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sheet_id", "event_id", "stratum"])
        for number in range(1, len(labels) + 1):
            writer.writerow([f"S{number:02d}", f"evt_{number:06d}", "s1"])
    return sheet, key


def test_labels_are_read_and_empty_rows_are_skipped(tmp_path):
    sheet, key = write_files(tmp_path, [SCAN, "", GUESS])
    rows = load_labels(sheet, key)
    assert [(r["sheet_id"], r["event_id"], r["label"]) for r in rows] == [
        ("S01", "evt_000001", SCAN),
        ("S03", "evt_000003", GUESS),
    ]


def test_a_label_that_is_not_a_class_key_stops_the_run_and_names_the_row(tmp_path):
    sheet, key = write_files(tmp_path, [SCAN, "scanner"])
    with pytest.raises(ValueError, match="S02"):
        load_labels(sheet, key)


def test_an_unlabelled_sheet_is_refused(tmp_path):
    sheet, key = write_files(tmp_path, ["", ""])
    with pytest.raises(ValueError, match="Fill in the label column"):
        load_labels(sheet, key)


def test_the_weights_follow_the_sessions_that_were_labelled_not_the_ones_sampled(
    tmp_path, monkeypatch, capsys
):
    sheet = tmp_path / "sheet.csv"
    with sheet.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sheet_id", "label", "notes"])
        # Four sampled, one skipped: S02 is left unlabelled.
        writer.writerows(
            [["S01", GUESS, ""], ["S02", "", ""], ["S03", SCAN, ""], ["S04", SCAN, ""]]
        )
    key = tmp_path / "key.csv"
    with key.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sheet_id", "event_id", "stratum"])
        writer.writerows([["S01", "evt_1", "big"], ["S02", "evt_2", "big"],
                          ["S03", "evt_3", "small"], ["S04", "evt_4", "small"]])
    strata = tmp_path / "strata.json"
    strata.write_text(
        json.dumps({"sizes": {"big": 100, "small": 10}, "sampled": {"big": 2, "small": 2}}),
        encoding="utf-8",
    )
    verdicts = tmp_path / "verdicts.jsonl"
    verdicts.write_text(
        "\n".join(json.dumps({"event_id": f"evt_{n}", "rules": {"label": SCAN}, "llm": None})
                  for n in range(1, 5)),
        encoding="utf-8",
    )
    argv = ["evaluate", "--labels", str(sheet), "--key", str(key),
            "--strata", str(strata), "--verdicts", str(verdicts)]
    monkeypatch.setattr(sys, "argv", argv)
    assert evaluate.main() == 0
    out = capsys.readouterr().out
    # The one labelled "big" row stands for all 100 big sessions and is wrong, and each "small"
    # row stands for 5 and is right: (5 + 5) / 110 = 9%. Weighting by the 2 sampled would give 17%.
    assert "Accuracy on the sample: 67%" in out
    assert "Re-weighted to the real strata: 9%" in out


def test_the_command_line_scores_the_rules_and_says_when_the_model_has_not_run(
    tmp_path, monkeypatch, capsys
):
    sheet, key = write_files(tmp_path, [SCAN, GUESS])
    strata = tmp_path / "strata.json"
    strata.write_text(json.dumps({"sizes": {"s1": 40}, "sampled": {"s1": 2}}), encoding="utf-8")
    verdicts = tmp_path / "verdicts.jsonl"
    verdicts.write_text(
        "\n".join(
            json.dumps({"event_id": f"evt_00000{n}", "rules": {"label": SCAN}, "llm": None})
            for n in (1, 2)
        ),
        encoding="utf-8",
    )
    argv = ["evaluate", "--labels", str(sheet), "--key", str(key),
            "--strata", str(strata), "--verdicts", str(verdicts)]
    monkeypatch.setattr(sys, "argv", argv)
    assert evaluate.main() == 0
    out = capsys.readouterr().out
    assert "## rules" in out and "Accuracy on the sample: 50%" in out
    assert "Not scored" in out and "## llm" in out
