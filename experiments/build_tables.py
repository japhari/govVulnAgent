#!/usr/bin/env python3
"""
Build markdown tables from experiment result JSON files.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build experiment result tables")
    p.add_argument("--results-dir", default="experiments/results", help="Directory containing result JSON files")
    p.add_argument("--output", default="experiments/results/TABLES.md", help="Output markdown file")
    return p.parse_args()


def to_row(name: str, metrics: dict, timing: dict) -> str:
    return (
        f"| {name} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | "
        f"{metrics['f1']:.3f} | {metrics['fpr']:.3f} | {timing['mtts_s_per_kloc']:.2f} |"
    )


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir)
    rows = []

    main_result_files = [
        ("Semgrep", "semgrep.json"),
        ("CodeBERT", "codebert.json"),
        ("GraphCodeBERT", "graphcodebert.json"),
        ("UniXcoder", "unixcoder.json"),
        ("DeepSeek-Coder-6.7B", "deepseek_coder_6_7b.json"),
        ("GovVulnAgent", "govvulnagent_full.json"),
    ]
    for label, filename in main_result_files:
        f = results_dir / filename
        if not f.exists():
            continue
        r = json.loads(f.read_text(encoding="utf-8"))
        rows.append(to_row(label, r["metrics"], r["timing"]))

    lines = [
        "# Experiment Tables",
        "",
        "## Main Results",
        "",
        "| Model | Precision | Recall | F1 | FPR | MTTS (s/KLOC) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    lines.extend(rows if rows else ["| (no results found) | - | - | - | - | - |"])

    ablation_summary = results_dir / "ablation" / "summary.json"
    if ablation_summary.exists():
        arr = json.loads(ablation_summary.read_text(encoding="utf-8"))
        lines.extend(
            [
                "",
                "## Ablation",
                "",
                "| Configuration | F1 | ΔF1 | MTTS (s/KLOC) |",
                "|---|---:|---:|---:|",
            ]
        )
        for row in arr:
            lines.append(
                f"| {row['configuration']} | {row['f1']:.3f} | {row['delta_f1_vs_full']:+.3f} | {row['mtts_s_per_kloc']:.2f} |"
            )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(str(out))


if __name__ == "__main__":
    main()

