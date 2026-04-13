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
    return p.parse_args()


def main() -> None:
    args = parse_args()
    langs = {x.strip().lower() for x in args.languages.split(",") if x.strip()}
    ratios = (args.train_ratio, args.val_ratio, args.test_ratio)
    if round(sum(ratios), 6) != 1.0:
        raise ValueError("train/val/test ratios must sum to 1.0")

    samples = load_jsonl(args.input)
    filtered: list[Sample] = [s for s in samples if s.language in langs]
    if not filtered:
        raise ValueError("No samples left after language filtering")

    train, val, test = split_dataset(filtered, ratios=ratios, seed=args.seed)
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

