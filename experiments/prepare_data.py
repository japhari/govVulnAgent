#!/usr/bin/env python3
"""
Prepare dataset splits for experiments.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.common import Sample, load_jsonl, split_dataset, write_jsonl


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Prepare experiment dataset splits")
    p.add_argument(
        "--input",
        default="data/cwe/govrepo_tz_dataset.jsonl",
        help="Input JSONL dataset",
    )
    p.add_argument(
        "--output-dir",
        default="experiments/data/govrepo_tz",
        help="Output directory for train/val/test JSONL files",
    )
    p.add_argument(
        "--languages",
        default="java,javascript,typescript",
        help="Comma-separated language filter",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--train-ratio", type=float, default=0.70)
    p.add_argument("--val-ratio", type=float, default=0.15)
    p.add_argument("--test-ratio", type=float, default=0.15)
    p.add_argument(
        "--drop-placeholders",
        action="store_true",
        help="Drop obvious placeholder samples (recommended)",
    )
    p.add_argument(
        "--min-lines",
        type=int,
        default=3,
        help="Drop samples shorter than this line count",
    )
    return p.parse_args()


def is_placeholder(sample: Sample) -> bool:
    text = (sample.code or "").strip().lower()
    if not text:
        return True
    placeholder_markers = [
        "placeholder code",
        "function_",
        "todo",
        "lorem ipsum",
    ]
    return any(marker in text for marker in placeholder_markers)


def stratified_split(
    samples: list[Sample],
    ratios: tuple[float, float, float],
    seed: int,
) -> tuple[list[Sample], list[Sample], list[Sample]]:
    """
    Stratify by (language, label) to keep class/language balance across splits.
    """
    buckets: dict[tuple[str, int], list[Sample]] = {}
    for s in samples:
        key = (s.language, s.label)
        buckets.setdefault(key, []).append(s)

    rnd = random.Random(seed)
    train: list[Sample] = []
    val: list[Sample] = []
    test: list[Sample] = []
    for group in buckets.values():
        rnd.shuffle(group)
        n = len(group)
        n_train = int(n * ratios[0])
        n_val = int(n * ratios[1])
        n_test = n - n_train - n_val

        # Keep non-empty validation/test for small-but-usable groups.
        if n >= 3 and n_val == 0:
            n_val = 1
            if n_train > 1:
                n_train -= 1
            elif n_test > 1:
                n_test -= 1
        if n >= 3 and n_test == 0:
            n_test = 1
            if n_train > 1:
                n_train -= 1
            elif n_val > 1:
                n_val -= 1

        g_train = group[:n_train]
        g_val = group[n_train : n_train + n_val]
        g_test = group[n_train + n_val : n_train + n_val + n_test]
        train.extend(g_train)
        val.extend(g_val)
        test.extend(g_test)

    rnd.shuffle(train)
    rnd.shuffle(val)
    rnd.shuffle(test)
    return train, val, test


def main() -> None:
    args = parse_args()
    langs = {x.strip().lower() for x in args.languages.split(",") if x.strip()}
    ratios = (args.train_ratio, args.val_ratio, args.test_ratio)
    if round(sum(ratios), 6) != 1.0:
        raise ValueError("train/val/test ratios must sum to 1.0")

    samples = load_jsonl(args.input)
    filtered: list[Sample] = [s for s in samples if s.language in langs]
    if args.min_lines > 0:
        filtered = [s for s in filtered if len((s.code or "").splitlines()) >= args.min_lines]
    dropped_placeholders = 0
    if args.drop_placeholders:
        before = len(filtered)
        filtered = [s for s in filtered if not is_placeholder(s)]
        dropped_placeholders = before - len(filtered)

    if not filtered:
        raise ValueError("No samples left after language filtering")

    train, val, test = stratified_split(filtered, ratios=ratios, seed=args.seed)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_jsonl(out_dir / "train.jsonl", train)
    write_jsonl(out_dir / "val.jsonl", val)
    write_jsonl(out_dir / "test.jsonl", test)

    summary = {
        "input": args.input,
        "output_dir": str(out_dir),
        "seed": args.seed,
        "ratios": {"train": args.train_ratio, "val": args.val_ratio, "test": args.test_ratio},
        "drop_placeholders": bool(args.drop_placeholders),
        "dropped_placeholders": dropped_placeholders,
        "min_lines": args.min_lines,
        "n_total": len(filtered),
        "n_train": len(train),
        "n_val": len(val),
        "n_test": len(test),
        "label_counts": dict(Counter(s.label for s in filtered)),
        "language_counts": dict(Counter(s.language for s in filtered)),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

