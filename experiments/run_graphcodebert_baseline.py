#!/usr/bin/env python3
"""
GraphCodeBERT baseline wrapper.
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run GraphCodeBERT baseline")
    p.add_argument("--dataset", required=True)
    p.add_argument("--train-dataset", default="")
    p.add_argument("--output", required=True)
    p.add_argument("--max-samples", type=int, default=0)
    p.add_argument("--max-train-samples", type=int, default=0)
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--device", default="auto")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cmd = [
        sys.executable,
        "experiments/run_encoder_centroid_baseline.py",
        "--model-name",
        "microsoft/graphcodebert-base",
        "--model-label",
        "GraphCodeBERT",
        "--dataset",
        args.dataset,
        "--output",
        args.output,
        "--max-samples",
        str(args.max_samples),
        "--max-train-samples",
        str(args.max_train_samples),
        "--batch-size",
        str(args.batch_size),
        "--max-length",
        str(args.max_length),
        "--device",
        args.device,
    ]
    if args.train_dataset:
        cmd.extend(["--train-dataset", args.train_dataset])
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()

