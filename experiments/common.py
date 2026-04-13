"""
Shared utilities for experiment scripts.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


LANGUAGE_ALIASES = {
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
}


EXT_BY_LANGUAGE = {
    "java": ".java",
    "javascript": ".js",
    "typescript": ".ts",
}


@dataclass
class Sample:
    sample_id: str
    language: str
    code: str
    label: int  # 1=vulnerable, 0=clean
    cwe_id: str = ""


def normalize_language(raw: str) -> str:
    key = (raw or "").strip().lower()
    return LANGUAGE_ALIASES.get(key, key)


def normalize_label(raw: str) -> int:
    val = str(raw).strip().lower()
    if val in {"1", "true", "vulnerable", "yes"}:
        return 1
    return 0


def load_jsonl(path: str | Path) -> List[Sample]:
    p = Path(path)
    samples: List[Sample] = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        obj = json.loads(line)
        samples.append(
            Sample(
                sample_id=str(obj.get("id", i)),
                language=normalize_language(str(obj.get("language", ""))),
                code=str(obj.get("code", "")),
                label=normalize_label(str(obj.get("label", ""))),
                cwe_id=str(obj.get("cwe_id", "")),
            )
        )
    return samples


def write_jsonl(path: str | Path, samples: Iterable[Sample]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(
                json.dumps(
                    {
                        "id": s.sample_id,
                        "language": s.language,
                        "code": s.code,
                        "label": "vulnerable" if s.label == 1 else "clean",
                        "cwe_id": s.cwe_id,
                    }
                )
                + "\n"
            )


def split_dataset(
    samples: Sequence[Sample],
    ratios: Tuple[float, float, float] = (0.7, 0.15, 0.15),
    seed: int = 42,
) -> Tuple[List[Sample], List[Sample], List[Sample]]:
    work = list(samples)
    rnd = random.Random(seed)
    rnd.shuffle(work)
    n = len(work)
    n_train = int(n * ratios[0])
    n_val = int(n * ratios[1])
    train = work[:n_train]
    val = work[n_train : n_train + n_val]
    test = work[n_train + n_val :]
    return train, val, test


def metrics_from_predictions(y_true: Sequence[int], y_pred: Sequence[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "n": len(y_true),
    }


def kloc_from_samples(samples: Sequence[Sample]) -> float:
    total_lines = sum(max(1, len(s.code.splitlines())) for s in samples)
    return max(total_lines / 1000.0, 0.001)

