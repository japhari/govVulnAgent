#!/usr/bin/env python3
"""
Run DeepSeek-Coder-6.7B baseline via Ollama.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from experiments.common import EXT_BY_LANGUAGE, kloc_from_samples, load_jsonl, metrics_from_predictions
from models.ollama_client import OllamaClient


SYSTEM_PROMPT = (
    "You are a secure code auditor. Return strictly JSON with keys: "
    "has_vulnerability (bool), confidence (float 0..1), cwe_ids (array of strings), "
    "description (string), severity (INFO|LOW|MEDIUM|HIGH|CRITICAL)."
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run DeepSeek-Coder baseline")
    p.add_argument("--dataset", required=True, help="JSONL dataset path")
    p.add_argument("--output", required=True, help="Output JSON result path")
    p.add_argument("--model", default="deepseek-coder:6.7b", help="Ollama model name")
    p.add_argument("--max-samples", type=int, default=0, help="Limit samples (0 = all)")
    p.add_argument("--confidence-threshold", type=float, default=0.6)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--llm-timeout", type=int, default=300)
    return p.parse_args()


def build_prompt(code: str, language: str) -> str:
    return (
        f"Analyze the following {language} code for security vulnerabilities.\n"
        "If vulnerable, include likely CWE ids.\n\n"
        "Return JSON only.\n\n"
        f"```{language}\n{code}\n```"
    )


async def run() -> None:
    args = parse_args()
    samples = [s for s in load_jsonl(args.dataset) if s.language in EXT_BY_LANGUAGE]
    if args.max_samples > 0:
        samples = samples[: args.max_samples]
    if not samples:
        raise ValueError("No compatible samples found for DeepSeek baseline")

    ollama = OllamaClient()
    ollama._client.timeout = float(args.llm_timeout)
    if not await ollama.is_available():
        raise RuntimeError("Ollama not reachable. Start it with: ollama serve")

    started = time.monotonic()
    y_true = []
    y_pred = []
    timeouts = 0
    total = len(samples)

    for i, s in enumerate(samples, start=1):
        prompt = build_prompt(s.code, s.language)
        result = None
        last_err = None
        for _ in range(max(1, args.retries + 1)):
            try:
                result = await ollama.generate_json(prompt, system=SYSTEM_PROMPT, model=args.model)
                break
            except Exception as e:  # noqa: PERF203
                last_err = e

        if result is None:
            if last_err and "timed out" in str(last_err).lower():
                timeouts += 1
            pred = 0
        else:
            has_v = bool(result.get("has_vulnerability", False))
            conf = result.get("confidence", 0.0)
            conf = float(conf) if isinstance(conf, (int, float, str)) else 0.0
            pred = 1 if (has_v and conf >= args.confidence_threshold) else 0

        y_true.append(s.label)
        y_pred.append(pred)
        elapsed = time.monotonic() - started
        eta = (elapsed / i) * (total - i)
        print(f"[deepseek] {i}/{total} pred={pred} elapsed={elapsed:.1f}s eta={eta:.1f}s", flush=True)

    elapsed = time.monotonic() - started
    kloc = kloc_from_samples(samples)
    metrics = metrics_from_predictions(y_true, y_pred)
    result = {
        "model": "DeepSeek-Coder-6.7B",
        "dataset": args.dataset,
        "samples": len(samples),
        "config": {
            "ollama_model": args.model,
            "confidence_threshold": float(args.confidence_threshold),
            "retries": int(args.retries),
            "llm_timeout": int(args.llm_timeout),
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

