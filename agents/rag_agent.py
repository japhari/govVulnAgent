"""
CVE/CWE RAG Agent — grounds semantic findings against locally indexed
NVD/CWE knowledge base using FAISS + sentence-transformers.
"""
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from config import (
    EMBEDDING_MODEL, FAISS_INDEX_PATH, FAISS_META_PATH,
    RAG_TOP_K, RAG_MIN_SIMILARITY,
)

logger = logging.getLogger(__name__)


@dataclass
class RAGResult:
    cwe_id: str
    cwe_name: str
    cve_ids: List[str]
    description: str
    remediation: str
    similarity: float
    references: List[str]


class CVECWERAGAgent:
    """
    Retrieves relevant CVE/CWE entries for a semantic finding
    using FAISS vector similarity search.
    """

    def __init__(self):
        self._index = None
        self._metadata = []
        self._embedder = None
        self._loaded = False
        self._load()

    def _load(self):
        """Load FAISS index and metadata. Graceful degradation if not available."""
        if not FAISS_INDEX_PATH.exists():
            logger.warning(
                "FAISS index not found at %s. RAG agent disabled. "
                "Run: python cli.py build-index --nvd-dir ./data/nvd --cwe-xml ./data/cwe/<cwe-xml-file>.xml",
                FAISS_INDEX_PATH,
            )
            return

        try:
            import faiss
            from sentence_transformers import SentenceTransformer

            self._index = faiss.read_index(str(FAISS_INDEX_PATH))
            with open(FAISS_META_PATH, "r") as f:
                self._metadata = json.load(f)
            self._embedder = SentenceTransformer(EMBEDDING_MODEL)
            self._loaded = True
            logger.info(
                "RAG index loaded: %d entries, embedding model: %s",
                self._index.ntotal,
                EMBEDDING_MODEL,
            )
        except ImportError as e:
            logger.warning("RAG dependencies not installed: %s", e)
        except Exception as e:
            logger.error("Failed to load RAG index: %s", e)

    def is_available(self) -> bool:
        return self._loaded

    async def retrieve(self, finding_description: str, cwe_ids: List[str]) -> List[RAGResult]:
        """
        Retrieve top-K relevant CVE/CWE entries for a finding.
        Falls back to CWE lookup by ID if FAISS is unavailable.
        """
        if not self._loaded:
            return self._fallback_lookup(cwe_ids)

        try:
            import numpy as np
            query = f"{finding_description} {' '.join(cwe_ids)}"
            vec = self._embedder.encode([query], normalize_embeddings=True)
            scores, indices = self._index.search(np.array(vec, dtype="float32"), RAG_TOP_K)

            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < 0 or score < RAG_MIN_SIMILARITY:
                    continue
                meta = self._metadata[idx]
                results.append(RAGResult(
                    cwe_id=meta.get("cwe_id", ""),
                    cwe_name=meta.get("cwe_name", ""),
                    cve_ids=meta.get("cve_ids", [])[:5],
                    description=meta.get("description", ""),
                    remediation=meta.get("remediation", ""),
                    similarity=float(score),
                    references=meta.get("references", [])[:3],
                ))
            return results

        except Exception as e:
            logger.error("RAG retrieval failed: %s", e)
            return self._fallback_lookup(cwe_ids)

    def _fallback_lookup(self, cwe_ids: List[str]) -> List[RAGResult]:
        """Static fallback for common CWEs when FAISS is unavailable."""
        STATIC_CWE = {
            "CWE-89": RAGResult(
                cwe_id="CWE-89", cwe_name="SQL Injection",
                cve_ids=["CVE-2023-23752", "CVE-2022-21500"],
                description="Improper neutralization of special elements used in an SQL command. Allows attackers to modify SQL queries.",
                remediation="Use parameterized queries or prepared statements. Apply input validation and principle of least privilege for DB accounts.",
                similarity=1.0,
                references=["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"],
            ),
            "CWE-79": RAGResult(
                cwe_id="CWE-79", cwe_name="Cross-site Scripting (XSS)",
                cve_ids=["CVE-2023-29469", "CVE-2022-23852"],
                description="Improper neutralization of input during web page generation. Allows attackers to inject client-side scripts.",
                remediation="Encode all user-controlled output. Use Content Security Policy (CSP). Avoid innerHTML; use textContent.",
                similarity=1.0,
                references=["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/79.html"],
            ),
            "CWE-22": RAGResult(
                cwe_id="CWE-22", cwe_name="Path Traversal",
                cve_ids=["CVE-2023-28252"],
                description="Improper limitation of a pathname to a restricted directory. Allows file system access outside intended directory.",
                remediation="Canonicalize paths. Validate against an allowlist of permitted directories. Use Path.normalize() and boundary checks.",
                similarity=1.0,
                references=["https://cwe.mitre.org/data/definitions/22.html"],
            ),
            "CWE-287": RAGResult(
                cwe_id="CWE-287", cwe_name="Improper Authentication",
                cve_ids=["CVE-2023-44487"],
                description="Authentication mechanism does not adequately verify the claimed identity of an actor.",
                remediation="Implement MFA. Use battle-tested authentication libraries. Validate JWT signatures server-side. Apply rate limiting.",
                similarity=1.0,
                references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
            ),
            "CWE-306": RAGResult(
                cwe_id="CWE-306", cwe_name="Missing Authentication for Critical Function",
                cve_ids=[],
                description="A critical function is accessible without authentication, exposing sensitive operations to unauthorized actors.",
                remediation="Add authentication guards to all sensitive endpoints. Apply @PreAuthorize or equivalent decorator. Implement deny-by-default access control.",
                similarity=1.0,
                references=["https://cwe.mitre.org/data/definitions/306.html"],
            ),
            "CWE-352": RAGResult(
                cwe_id="CWE-352", cwe_name="Cross-Site Request Forgery (CSRF)",
                cve_ids=[],
                description="Web application does not verify that a request was intentionally sent by the user. Allows forged cross-origin requests.",
                remediation="Use CSRF tokens (Synchronizer Token Pattern). Enable SameSite=Strict cookie attribute. Verify Origin and Referer headers.",
                similarity=1.0,
                references=["https://owasp.org/www-community/attacks/csrf", "https://cwe.mitre.org/data/definitions/352.html"],
            ),
        }
        results = []
        for cwe_id in cwe_ids:
            if cwe_id in STATIC_CWE:
                results.append(STATIC_CWE[cwe_id])
        return results


# ── Index Builder Helper ──────────────────────────────────────────────────────
# Run via CLI: python cli.py build-index --nvd-dir ./data/nvd --cwe-xml ./data/cwe/<cwe-xml-file>.xml
# Requires: NVD JSON feeds in data/nvd/ and MITRE CWE XML in data/cwe/

def build_index_from_nvd(nvd_dir: str, cwe_xml_path: str, output_dir: str):
    """
    Offline script to build FAISS index from NVD annual JSON feeds.

    nvd_dir: directory containing NVD JSON feed files (nvdcve-1.1-2018.json, etc.)
    cwe_xml_path: path to MITRE CWE research concepts XML
    output_dir: output directory for FAISS index and metadata
    """
    import json, glob
    from pathlib import Path

    try:
        import faiss
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("Install: pip install faiss-cpu sentence-transformers")
        return

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model = SentenceTransformer(EMBEDDING_MODEL)
    records = []

    # Load NVD entries
    feed_files = sorted(glob.glob(str(Path(nvd_dir) / "*.json")))
    if not feed_files:
        raise ValueError(
            f"No NVD JSON files found in '{nvd_dir}'. "
            "Download NVD feeds and place .json files in that directory."
        )

    for feed_file in feed_files:
        with open(feed_file) as f:
            data = json.load(f)
        for item in data.get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            descs = item["cve"]["description"]["description_data"]
            desc = descs[0]["value"] if descs else ""
            cwes = [
                n["value"]
                for pd in item["cve"].get("problemtype", {}).get("problemtype_data", [])
                for n in pd.get("description", [])
                if n["value"].startswith("CWE-")
            ]
            records.append({
                "cve_id": cve_id, "cwe_id": cwes[0] if cwes else "",
                "cwe_ids": cwes, "description": desc[:512], "cwe_name": "",
                "remediation": "", "references": [],
            })

    print(f"Loaded {len(records)} CVE records")
    if not records:
        raise ValueError(
            "Loaded 0 CVE records from NVD feeds. "
            "Ensure feed files contain a 'CVE_Items' array and are not empty."
        )

    texts = [f"{r['cwe_id']} {r['description']}" for r in records]
    print("Encoding embeddings...")
    embeddings = model.encode(texts, batch_size=256, show_progress_bar=True, normalize_embeddings=True)

    if len(embeddings.shape) != 2 or embeddings.shape[0] == 0:
        raise ValueError("Failed to build embeddings from NVD records (empty embedding matrix).")

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(np.array(embeddings, dtype="float32"))

    faiss.write_index(index, str(out_dir / "nvd_cwe.faiss"))
    with open(out_dir / "nvd_cwe_meta.json", "w") as f:
        json.dump(records, f)

    print(f"Index built: {index.ntotal} vectors → {out_dir}")
