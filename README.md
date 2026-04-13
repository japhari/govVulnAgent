# GovVulnAgent 🛡️

**Sovereign Multi-Agent LLM Framework for Code Vulnerability Detection in Government Information Systems**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Model: Qwen2.5-Coder-32B](https://img.shields.io/badge/Model-Qwen2.5--Coder--32B-green.svg)](https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct)

> *Companion code for the paper: "GovVulnAgent: A Multi-Agent Large Language Model Framework for Sovereign Code Vulnerability Detection in Government Information Systems"*

---

## Overview

GovVulnAgent detects security vulnerabilities in government codebases using a six-agent pipeline powered by a locally deployed LLM — **no cloud dependency, no data exfiltration**.

### Agent Pipeline

```
Repository
    │
    ▼
┌─────────────────┐
│  Orchestrator   │  ← task decomposition, file routing
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌─────────────────┐
│ Code   │ │ Static          │
│ Parser │ │ Heuristics      │  ← Semgrep tool call
│ Agent  │ │ Agent           │
└───┬────┘ └───────┬─────────┘
    │               │ hints
    └───────┬───────┘
            ▼
┌───────────────────────┐
│  Semantic Vulnerability│  ← Qwen2.5-Coder-32B (Ollama)
│  Agent (CoT prompting) │     chain-of-thought reasoning
└───────────┬───────────┘
            │ findings
            ▼
┌───────────────────────┐
│   CVE/CWE RAG Agent   │  ← FAISS + NVD + MITRE CWE
│  (knowledge grounding)│
└───────────┬───────────┘
            │ enriched findings
            ▼
┌───────────────────────┐
│     Report Agent      │  ← CVSS 3.1 scoring, dedup
│  (JSON + Markdown)    │     structured output
└───────────────────────┘
```

### Supported Languages

| Language | Framework | Extensions |
|----------|-----------|------------|
| Java | Spring Boot | `.java` |
| JavaScript | React, Node.js | `.js`, `.jsx` |
| TypeScript | Angular, NestJS | `.ts`, `.tsx` |

### Top CWEs Detected

CWE-89 (SQL Injection), CWE-79 (XSS), CWE-22 (Path Traversal), CWE-287 (Improper Authentication), CWE-306 (Missing Authentication), CWE-352 (CSRF), CWE-613 (Session Expiration), CWE-285 (Improper Authorization)

---

## Hardware Requirements

| Config | GPU | VRAM | Speed |
|--------|-----|------|-------|
| **Recommended** | NVIDIA A100 40GB | 40 GB | 2.3 KLOC/min |
| **Minimum** | NVIDIA RTX 3090/4090 | 24 GB | ~1.2 KLOC/min (4-bit) |
| **CPU-only** | — | — | Very slow (~0.05 KLOC/min) |

---

## Quick Start

### 1. Install Ollama and pull the model

```bash
# Install Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the primary model (~20GB, 4-bit quantized)
ollama pull qwen2.5-coder:32b

# Or use the smaller fallback for limited hardware
ollama pull codellama:34b
```

### 2. Install Python dependencies

```bash
git clone https://github.com/your-org/govvulnagent
cd govvulnagent
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> If your environment supports virtualenv, you can optionally create and activate one before installing dependencies.

### 3. (Optional) Build the RAG index

Prepare datasets first:

```bash
mkdir -p data/nvd data/cwe
```

**Option A — NVD legacy feed files (recommended when available):**

Download one or more NVD feed `.json` files into `./data/nvd` from https://nvd.nist.gov/vuln/data-feeds.

**Option B — NVD API snapshot (works in restricted environments):**

```bash
python - <<'PY'
import json, urllib.request
from pathlib import Path

url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000"
raw = json.loads(urllib.request.urlopen(url, timeout=60).read().decode("utf-8"))
items = []
for v in raw.get("vulnerabilities", []):
    c = v.get("cve", {})
    cve_id = c.get("id", "")
    desc = ""
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and c.get("descriptions"):
        desc = c["descriptions"][0].get("value", "")
    cwes = []
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            value = d.get("value", "")
            if isinstance(value, str) and value.startswith("CWE-"):
                cwes.append(value)
    items.append({
        "cve": {
            "CVE_data_meta": {"ID": cve_id},
            "description": {"description_data": [{"value": desc}]},
            "problemtype": {"problemtype_data": [{"description": [{"value": w} for w in cwes]}]},
        }
    })
Path("data/nvd").mkdir(parents=True, exist_ok=True)
Path("data/nvd/nvdcve-1.1-api-snapshot.json").write_text(json.dumps({"CVE_Items": items}), encoding="utf-8")
print(f"Wrote {len(items)} CVE items")
PY
```

Download and extract the latest CWE XML:

```bash
curl -L "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip" -o data/cwe/cwec_latest.xml.zip
unzip -o data/cwe/cwec_latest.xml.zip -d data/cwe
```

Then build the index (replace XML filename if needed):

```bash
python cli.py build-index \
  --nvd-dir ./data/nvd \
  --cwe-xml ./data/cwe/cwec_v4.19.1.xml

# verify
python cli.py status
```

*Without the RAG index, the system uses a built-in static fallback for the top 20 CWEs — still functional but less comprehensive.*

### 4. Scan a repository

**CLI:**
```bash
# Check status
python cli.py status

# Scan a repository
python cli.py scan /path/to/government-repo

# Scan Java only
python cli.py scan /path/to/repo --pattern "**/*.java"

# Save JSON report
python cli.py scan /path/to/repo --output scan_report.json
```

**REST API:**
```bash
# Start the API server
python main.py

# Scan (async, returns scan_id)
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_path": "/path/to/repo"}'

# Retrieve report
curl http://localhost:8080/report/{scan_id}

# Scan synchronously (blocks)
curl -X POST http://localhost:8080/scan/sync \
  -H "Content-Type: application/json" \
  -d '{"repository_path": "/path/to/repo", "max_files": 10}'

# Upload and scan a single file
curl -X POST http://localhost:8080/scan/file \
  -F "file=@vulnerable.java"
```

**Docker Compose (recommended for production):**
```bash
docker compose up -d
docker compose exec ollama ollama pull qwen2.5-coder:32b
curl http://localhost:8080/status
```

---

## Example Output

**JSON Report (excerpt):**
```json
{
  "scan_id": "a3f2c1b0",
  "summary": {
    "total_files": 47,
    "total_chunks": 312,
    "total_vulnerabilities": 8,
    "by_severity": { "CRITICAL": 2, "HIGH": 4, "MEDIUM": 2 }
  },
  "findings": [
    {
      "file_path": "src/main/java/dao/UserDao.java",
      "function_name": "findByUsername",
      "lines": "23-31",
      "has_vulnerability": true,
      "cwe_ids": ["CWE-89"],
      "description": "SQL injection via string concatenation in JDBC query",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "confidence": 0.97,
      "remediation": "Use parameterized queries or PreparedStatement..."
    }
  ]
}
```

---

## Dataset: GovRepo-TZ

The GovRepo-TZ benchmark dataset (1,247 labeled functions from Tanzanian government repositories) will be released on Zenodo upon paper acceptance.
This repository currently includes a local development dataset file at `data/cwe/govrepo_tz_dataset.jsonl` for testing pipeline behavior.

| Split | Vulnerable | Clean | Total |
|-------|-----------|-------|-------|
| Train | 453 | 420 | 873 |
| Val   | 97  | 90  | 187  |
| Test  | 97  | 90  | 187  |

Languages in benchmark paper split: Java (512), JavaScript (398), TypeScript (337)

---

## Benchmark Results

The table below reports paper benchmark metrics. Reproducing these exact values requires the same curated splits, model checkpoints, and runtime environment used in the study.

| Model | Precision | Recall | F1 | FPR |
|-------|-----------|--------|----|-----|
| Semgrep | 0.71 | 0.58 | 0.64 | 0.21 |
| CodeBERT | 0.79 | 0.74 | 0.76 | 0.14 |
| GraphCodeBERT | 0.82 | 0.77 | 0.79 | 0.12 |
| UniXcoder | 0.84 | 0.79 | 0.81 | 0.11 |
| DeepSeek-Coder-6.7B | 0.83 | 0.81 | 0.82 | 0.10 |
| GPT-4o (cloud†) | 0.86 | 0.88 | 0.87 | 0.09 |
| **GovVulnAgent (ours)** | **0.88** | **0.91** | **0.89** | **0.08** |

*†GPT-4o is a cloud-only reference; not suitable for sovereign government deployment.*

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v -k "TestCodeParser"   # specific class
pytest tests/ -v --asyncio-mode=auto   # async tests
```

---

## Project Structure

```
govvulnagent/
├── main.py                    # FastAPI REST API
├── cli.py                     # Command-line interface
├── config.py                  # Configuration
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── agents/
│   ├── orchestrator.py        # Main pipeline coordinator
│   ├── parser_agent.py        # tree-sitter AST chunking
│   ├── static_agent.py        # Semgrep wrapper
│   ├── semantic_agent.py      # Qwen2.5-Coder LLM analysis
│   ├── rag_agent.py           # FAISS + NVD/CWE RAG
│   └── report_agent.py        # CVSS scoring + report generation
├── models/
│   └── ollama_client.py       # Async Ollama API client
├── data/
│   └── cwe/                   # FAISS index (built offline)
├── reports/                   # Scan output directory
└── tests/
    └── test_govvulnagent.py
```

---

## Citation

```bibtex
@inproceedings{mwangi2026govvulnagent,
  title     = {{GovVulnAgent}: A Multi-Agent Large Language Model Framework
               for Sovereign Code Vulnerability Detection in Government
               Information Systems},
  author    = {Mwangi, Jeph and Kitali, Erick and Kapologwe, Ntuli},
  booktitle = {Proceedings of the IEEE [Target Conference]},
  year      = {2026},
  address   = {Tanzania},
}
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

*Developed at PO-RALG, United Republic of Tanzania, in collaboration with ECSA-HC.*
