#!/usr/bin/env python3
"""
Run embedding-centroid baselines (CodeBERT/GraphCodeBERT/UniXcoder style).
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

from experiments.common import EXT_BY_LANGUAGE, kloc_from_samples, load_jsonl, metrics_from_predictions


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run encoder centroid baseline")
    p.add_argument("--model-name", required=True, help="HuggingFace model id")
    p.add_argument("--model-label", required=True, help="Display label in output")
    p.add_argument("--dataset", required=True, help="Test JSONL dataset path")
    p.add_argument("--train-dataset", default="", help="Train JSONL dataset path (default: sibling train.jsonl)")
    p.add_argument("--output", required=True, help="Output JSON result path")
    p.add_argument("--max-samples", type=int, default=0, help="Limit test samples (0 = all)")
    p.add_argument("--max-train-samples", type=int, default=0, help="Limit train samples (0 = all)")
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--device", default="auto", help="auto/cpu/cuda")
    return p.parse_args()


def resolve_train_dataset(test_dataset: str, train_dataset: str) -> str:
    if train_dataset:
        return train_dataset
    test_path = Path(test_dataset)
    if test_path.name == "test.jsonl":
        candidate = test_path.with_name("train.jsonl")
        if candidate.exists():
            return str(candidate)
    raise ValueError("train dataset not provided and could not infer sibling train.jsonl")


def select_device(requested: str) -> torch.device:
    if requested == "cpu":
        return torch.device("cpu")
    if requested == "cuda":
        return torch.device("cuda")
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def embed_texts(
    texts: list[str],
    tokenizer,
    model,
    device: torch.device,
    batch_size: int,
    max_length: int,
) -> np.ndarray:
    vectors: list[np.ndarray] = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            toks = tokenizer(
                batch,
                truncation=True,
                max_length=max_length,
                padding=True,
                return_tensors="pt",
            )
            toks = {k: v.to(device) for k, v in toks.items()}
            out = model(**toks)
            hidden = out.last_hidden_state
            mask = toks["attention_mask"].unsqueeze(-1).to(hidden.dtype)
            pooled = (hidden * mask).sum(dim=1) / torch.clamp(mask.sum(dim=1), min=1e-9)
            pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
            vectors.extend(pooled.cpu().numpy())
    return np.asarray(vectors, dtype=np.float32)


def centroid(vs: np.ndarray) -> np.ndarray:
    c = vs.mean(axis=0)
    n = np.linalg.norm(c)
    if n < 1e-12:
        return c
    return c / n


def cosine_batch(vs: np.ndarray, c: np.ndarray) -> np.ndarray:
    return vs @ c


def main() -> None:
    args = parse_args()
    device = select_device(args.device)

    train_path = resolve_train_dataset(args.dataset, args.train_dataset)
    train = [s for s in load_jsonl(train_path) if s.language in EXT_BY_LANGUAGE]
    test = [s for s in load_jsonl(args.dataset) if s.language in EXT_BY_LANGUAGE]
    if args.max_train_samples > 0:
        train = train[: args.max_train_samples]
    if args.max_samples > 0:
        test = test[: args.max_samples]
    if not train:
        raise ValueError("No compatible train samples found")
    if not test:
        raise ValueError("No compatible test samples found")

    tokenizer = AutoTokenizer.from_pretrained(args.model_name, trust_remote_code=True)
    model = AutoModel.from_pretrained(args.model_name, trust_remote_code=True).to(device)

    train_texts = [s.code for s in train]
    test_texts = [s.code for s in test]

    started = time.monotonic()
    print(f"[{args.model_label}] Embedding train samples: {len(train_texts)}", flush=True)
    train_vecs = embed_texts(train_texts, tokenizer, model, device, args.batch_size, args.max_length)
    print(f"[{args.model_label}] Embedding test samples: {len(test_texts)}", flush=True)
    test_vecs = embed_texts(test_texts, tokenizer, model, device, args.batch_size, args.max_length)

    y_train = np.asarray([s.label for s in train], dtype=np.int64)
    y_true = [s.label for s in test]

    pos = train_vecs[y_train == 1]
    neg = train_vecs[y_train == 0]
    if len(pos) == 0 or len(neg) == 0:
        raise ValueError("Train split must contain both vulnerable and clean samples")

    c_pos = centroid(pos)
    c_neg = centroid(neg)
    s_pos = cosine_batch(test_vecs, c_pos)
    s_neg = cosine_batch(test_vecs, c_neg)
    y_pred = [1 if a >= b else 0 for a, b in zip(s_pos, s_neg)]

    elapsed = time.monotonic() - started
    kloc = kloc_from_samples(test)
    metrics = metrics_from_predictions(y_true, y_pred)
    result = {
        "model": args.model_label,
        "hf_model": args.model_name,
        "dataset": args.dataset,
        "train_dataset": train_path,
        "samples": len(test),
        "training_samples": len(train),
        "classifier": "embedding_centroid_cosine",
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
    main()

