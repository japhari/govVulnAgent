#!/usr/bin/env python3
"""
Run Semgrep-only baseline on a JSONL function dataset.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.static_agent import StaticHeuristicsAgent
from experiments.common import EXT_BY_LANGUAGE, kloc_from_samples, load_jsonl, metrics_from_predictions


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Semgrep baseline")
    p.add_argument("--dataset", required=True, help="JSONL dataset path")
    p.add_argument("--output", required=True, help="Output JSON result path")
    p.add_argument("--max-samples", type=int, default=0, help="Limit samples (0 = all)")
    return p.parse_args()


async def run() -> None:
    args = parse_args()
    samples = load_jsonl(args.dataset)
    samples = [s for s in samples if s.language in EXT_BY_LANGUAGE]
    if args.max_samples > 0:
        samples = samples[: args.max_samples]
    if not samples:
        raise ValueError("No compatible samples found for Semgrep baseline")

    agent = StaticHeuristicsAgent()
    y_true = []
    y_pred = []
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="semgrep-baseline-") as td:
        tmp_dir = Path(td)
        for s in samples:
            ext = EXT_BY_LANGUAGE[s.language]
            path = tmp_dir / f"{s.sample_id}{ext}"
            path.write_text(s.code, encoding="utf-8")
            findings = await agent.scan_file(str(path), s.language)
            pred = 1 if findings else 0
            y_true.append(s.label)
            y_pred.append(pred)

    elapsed = time.monotonic() - started
    kloc = kloc_from_samples(samples)
    metrics = metrics_from_predictions(y_true, y_pred)
    result = {
        "model": "Semgrep",
        "dataset": args.dataset,
        "samples": len(samples),
        "metrics": metrics,
        "timing": {
            "elapsed_seconds": round(elapsed, 3),
            "kloc": round(kloc, 3),
            "mtts_s_per_kloc": round(elapsed / kloc, 3),
        },
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(run())

