#!/usr/bin/env python3
"""
Run GovVulnAgent-style evaluation on a JSONL function dataset.

This script evaluates per-function samples by creating in-memory CodeChunk objects
and applying Static -> Semantic -> (optional) RAG flow.
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

from agents.parser_agent import CodeChunk
from agents.rag_agent import CVECWERAGAgent
from agents.semantic_agent import SemanticVulnerabilityAgent
from agents.static_agent import StaticHeuristicsAgent
from experiments.common import EXT_BY_LANGUAGE, kloc_from_samples, load_jsonl, metrics_from_predictions
from models.ollama_client import OllamaClient


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run GovVulnAgent evaluation")
    p.add_argument("--dataset", required=True, help="JSONL dataset path")
    p.add_argument("--output", required=True, help="Output JSON result path")
    p.add_argument("--max-samples", type=int, default=50, help="Limit samples (default 50)")
    p.add_argument("--disable-static", action="store_true")
    p.add_argument("--disable-rag", action="store_true")
    p.add_argument("--disable-cot", action="store_true")
    p.add_argument("--single-agent", action="store_true", help="Equivalent to no-static,no-rag,no-cot")
    return p.parse_args()


async def run() -> None:
    args = parse_args()
    if args.single_agent:
        args.disable_static = True
        args.disable_rag = True
        args.disable_cot = True

    samples = load_jsonl(args.dataset)
    samples = [s for s in samples if s.language in EXT_BY_LANGUAGE]
    if args.max_samples > 0:
        samples = samples[: args.max_samples]
    if not samples:
        raise ValueError("No compatible samples found for GovVulnAgent evaluation")

    # Optional ablation: remove few-shot examples and shorten reasoning guidance.
    if args.disable_cot:
        import agents.semantic_agent as semantic_mod

        semantic_mod._FEW_SHOT = {k: "" for k in semantic_mod._FEW_SHOT.keys()}
        semantic_mod._SYSTEM_PROMPT = (
            "You are a security reviewer. Return JSON only with keys: "
            "has_vulnerability, cwe_ids, description, severity, confidence, reasoning."
        )

    ollama = OllamaClient()
    semantic = SemanticVulnerabilityAgent(ollama)
    static = None if args.disable_static else StaticHeuristicsAgent()
    rag = None if args.disable_rag else CVECWERAGAgent()

    y_true = []
    y_pred = []
    timeouts = 0
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="govvulnagent-eval-") as td:
        tmp_dir = Path(td)
        for s in samples:
            ext = EXT_BY_LANGUAGE[s.language]
            file_path = tmp_dir / f"{s.sample_id}{ext}"
            file_path.write_text(s.code, encoding="utf-8")

            line_count = max(1, len(s.code.splitlines()))
            chunk = CodeChunk(
                file_path=str(file_path),
                language=s.language,
                function_name=f"sample_{s.sample_id}",
                class_name=None,
                start_line=1,
                end_line=line_count,
                source=s.code,
                annotations=[],
                is_priority=False,
                token_estimate=len(s.code.split()) * 2,
            )

            hints = "No static analysis findings for this chunk."
            if static is not None:
                sf = await static.scan_file(str(file_path), s.language)
                hints = static.hints_for_chunk(sf, 1, line_count)

            finding = await semantic.analyze_chunk(chunk, hints)
            if "timed out" in (finding.description or "").lower():
                timeouts += 1
            y_true.append(s.label)
            y_pred.append(1 if finding.has_vulnerability else 0)

            if rag is not None and finding.has_vulnerability:
                await rag.retrieve(finding.description, finding.cwe_ids)

    elapsed = time.monotonic() - started
    kloc = kloc_from_samples(samples)
    metrics = metrics_from_predictions(y_true, y_pred)
    result = {
        "model": "GovVulnAgent",
        "dataset": args.dataset,
        "samples": len(samples),
        "config": {
            "disable_static": bool(args.disable_static),
            "disable_rag": bool(args.disable_rag),
            "disable_cot": bool(args.disable_cot),
            "single_agent": bool(args.single_agent),
        },
        "metrics": metrics,
        "timing": {
            "elapsed_seconds": round(elapsed, 3),
            "kloc": round(kloc, 3),
            "mtts_s_per_kloc": round(elapsed / kloc, 3),
        },
        "timeouts": timeouts,
    }

    await ollama.close()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(run())

