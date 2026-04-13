#!/usr/bin/env python3
"""
Run GovVulnAgent ablation configurations and summarize delta F1.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run GovVulnAgent ablations")
    p.add_argument("--dataset", required=True, help="JSONL dataset path")
    p.add_argument("--output-dir", default="experiments/results/ablation", help="Output dir")
    p.add_argument("--max-samples", type=int, default=30, help="Max samples per run")
    return p.parse_args()


def run_case(name: str, flags: list[str], dataset: str, output_dir: Path, max_samples: int) -> Path:
    out = output_dir / f"{name}.json"
    cmd = [
        sys.executable,
        "experiments/run_govvulnagent_eval.py",
        "--dataset",
        dataset,
        "--output",
        str(out),
        "--max-samples",
        str(max_samples),
    ] + flags
    subprocess.run(cmd, check=True)
    return out


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cases = [
        ("full", []),
        ("no_static", ["--disable-static"]),
        ("no_rag", ["--disable-rag"]),
        ("no_cot", ["--disable-cot"]),
        ("single_agent", ["--single-agent"]),
    ]

    outputs = []
    for name, flags in cases:
        out = run_case(name, flags, args.dataset, out_dir, args.max_samples)
        outputs.append(out)

    loaded = {}
    for p in outputs:
        loaded[p.stem] = json.loads(p.read_text(encoding="utf-8"))

    full_f1 = loaded["full"]["metrics"]["f1"]
    summary = []
    for name in ["full", "no_static", "no_rag", "no_cot", "single_agent"]:
        f1 = loaded[name]["metrics"]["f1"]
        summary.append(
            {
                "configuration": name,
                "f1": f1,
                "delta_f1_vs_full": round(f1 - full_f1, 4),
                "mtts_s_per_kloc": loaded[name]["timing"]["mtts_s_per_kloc"],
            }
        )

    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

