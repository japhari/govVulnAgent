#!/usr/bin/env python3
"""
Run Semgrep-only baseline on a JSONL function dataset.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
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
    p.add_argument(
        "--rule-config",
        default="",
        help="Semgrep config path (YAML). If omitted, uses default StaticHeuristicsAgent packs.",
    )
    return p.parse_args()


def run_semgrep_with_config(file_path: str, rule_config: str, timeout_s: int = 60) -> int:
    cmd = [
        "semgrep",
        "--json",
        "--no-git-ignore",
        "--timeout",
        str(timeout_s),
        "--config",
        rule_config,
        file_path,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 10)
    except Exception:
        return 0

    if res.returncode not in (0, 1):
        return 0
    try:
        data = json.loads(res.stdout)
        return len(data.get("results", []))
    except Exception:
        return 0


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
    total = len(samples)
    print(f"[baseline] Starting Semgrep on {total} samples...", flush=True)

    with tempfile.TemporaryDirectory(prefix="semgrep-baseline-") as td:
        tmp_dir = Path(td)
        for i, s in enumerate(samples, start=1):
            ext = EXT_BY_LANGUAGE[s.language]
            path = tmp_dir / f"{s.sample_id}{ext}"
            path.write_text(s.code, encoding="utf-8")
            if args.rule_config:
                finding_count = run_semgrep_with_config(str(path), args.rule_config)
            else:
                findings = await agent.scan_file(str(path), s.language)
                finding_count = len(findings)
            pred = 1 if finding_count > 0 else 0
            y_true.append(s.label)
            y_pred.append(pred)

            elapsed = time.monotonic() - started
            avg = elapsed / i
            eta = avg * (total - i)
            print(
                f"[baseline] {i}/{total} "
                f"lang={s.language} findings={finding_count} "
                f"elapsed={elapsed:.1f}s eta={eta:.1f}s",
                flush=True,
            )

    elapsed = time.monotonic() - started
    kloc = kloc_from_samples(samples)
    metrics = metrics_from_predictions(y_true, y_pred)
    result = {
        "model": "Semgrep",
        "dataset": args.dataset,
        "samples": len(samples),
        "rule_config": args.rule_config or "default_static_agent_configs",
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

