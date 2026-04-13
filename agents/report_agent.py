"""
Report Agent — deduplicates findings, computes CVSS scores,
and generates structured JSON and Markdown security reports.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from agents.semantic_agent import SemanticFinding
from agents.rag_agent import RAGResult
from config import SEVERITY_MAP, REPORT_OUTPUT_DIR

logger = logging.getLogger(__name__)


@dataclass
class EnrichedFinding:
    finding: SemanticFinding
    rag_results: List[RAGResult]
    cvss_score: float
    cvss_vector: str
    deduplicated: bool = False

    def to_dict(self) -> dict:
        return {
            **self.finding.to_dict(),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve_references": [r.cve_ids for r in self.rag_results],
            "remediation": self._best_remediation(),
            "knowledge_base_matches": [
                {"cwe_id": r.cwe_id, "cwe_name": r.cwe_name, "similarity": r.similarity}
                for r in self.rag_results
            ],
        }

    def _best_remediation(self) -> str:
        for r in self.rag_results:
            if r.remediation:
                return r.remediation
        return "Refer to OWASP Top-10 and NIST CWE guidance for this vulnerability class."


@dataclass
class ScanReport:
    scan_id: str
    repository_path: str
    scan_timestamp: str
    total_files_scanned: int
    total_chunks_analyzed: int
    total_vulnerabilities: int
    findings_by_severity: Dict[str, int]
    findings: List[EnrichedFinding]
    language_breakdown: Dict[str, int]
    scan_duration_seconds: float
    model_used: str

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "repository_path": self.repository_path,
            "scan_timestamp": self.scan_timestamp,
            "model": self.model_used,
            "summary": {
                "total_files": self.total_files_scanned,
                "total_chunks": self.total_chunks_analyzed,
                "total_vulnerabilities": self.total_vulnerabilities,
                "by_severity": self.findings_by_severity,
                "by_language": self.language_breakdown,
                "scan_duration_s": round(self.scan_duration_seconds, 2),
            },
            "findings": [f.to_dict() for f in self.findings if f.finding.has_vulnerability],
        }

    def to_markdown(self) -> str:
        ts = self.scan_timestamp
        lines = [
            "# GovVulnAgent Security Scan Report",
            f"",
            f"**Scan ID:** `{self.scan_id}`  ",
            f"**Repository:** `{self.repository_path}`  ",
            f"**Timestamp:** {ts}  ",
            f"**Model:** {self.model_used}  ",
            f"**Duration:** {self.scan_duration_seconds:.1f}s  ",
            f"",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Files Scanned | {self.total_files_scanned} |",
            f"| Code Chunks Analyzed | {self.total_chunks_analyzed} |",
            f"| Vulnerabilities Found | {self.total_vulnerabilities} |",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.findings_by_severity.get(sev, 0)
            if count:
                lines.append(f"| {sev} | {count} |")
        lines += ["", "---", "", "## Detailed Findings", ""]

        vuln_findings = [f for f in self.findings if f.finding.has_vulnerability]
        if not vuln_findings:
            lines.append("✅ No vulnerabilities detected.")
        else:
            for i, ef in enumerate(vuln_findings, 1):
                f = ef.finding
                cwes = ", ".join(f.cwe_ids) or "Unknown"
                lines += [
                    f"### Finding {i}: {f.severity} — {cwes}",
                    f"",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **File** | `{f.file_path}` |",
                    f"| **Function** | `{f.function_name}` |",
                    f"| **Lines** | {f.start_line}–{f.end_line} |",
                    f"| **Language** | {f.language} |",
                    f"| **CWE** | {cwes} |",
                    f"| **CVSS Score** | {ef.cvss_score:.1f} |",
                    f"| **Confidence** | {f.confidence:.0%} |",
                    f"",
                    f"**Description:** {f.description}",
                    f"",
                    f"**Reasoning:**",
                    f"> {f.reasoning}",
                    f"",
                    f"**Remediation:** {ef._best_remediation()}",
                    f"",
                ]
                if ef.rag_results:
                    lines.append("**Related CVE References:**")
                    for r in ef.rag_results:
                        if r.cve_ids:
                            lines.append(f"- {r.cwe_id} ({r.cwe_name}): {', '.join(r.cve_ids[:3])}")
                lines += ["", "---", ""]

        lines += [
            "## Language Breakdown",
            "",
            "| Language | Vulnerable Chunks |",
            "|----------|------------------|",
        ]
        for lang, count in self.language_breakdown.items():
            lines.append(f"| {lang} | {count} |")

        lines += ["", "---", "", "*Generated by GovVulnAgent — Sovereign AI Code Security Scanner*"]
        return "\n".join(lines)


class ReportAgent:
    """
    Aggregates enriched findings, deduplicates, scores with CVSS,
    and produces both JSON and Markdown reports.
    """

    def build_report(
        self,
        scan_id: str,
        repository_path: str,
        findings: List[SemanticFinding],
        rag_map: Dict[str, List[RAGResult]],  # chunk_id -> RAG results
        total_files: int,
        total_chunks: int,
        scan_duration: float,
        model_used: str,
    ) -> ScanReport:
        # Enrich each finding
        enriched = []
        for f in findings:
            rag = rag_map.get(f.chunk_id, [])
            cvss, vec = self._compute_cvss(f.severity, f.cwe_ids)
            enriched.append(EnrichedFinding(
                finding=f,
                rag_results=rag,
                cvss_score=cvss,
                cvss_vector=vec,
            ))

        # Deduplicate
        enriched = self._deduplicate(enriched)

        # Sort by CVSS descending
        enriched.sort(key=lambda x: x.cvss_score, reverse=True)

        vuln_findings = [e for e in enriched if e.finding.has_vulnerability]
        severity_counts: Dict[str, int] = {}
        lang_counts: Dict[str, int] = {}
        for e in vuln_findings:
            sev = e.finding.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            lang = e.finding.language
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        return ScanReport(
            scan_id=scan_id,
            repository_path=repository_path,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            total_files_scanned=total_files,
            total_chunks_analyzed=total_chunks,
            total_vulnerabilities=len(vuln_findings),
            findings_by_severity=severity_counts,
            findings=enriched,
            language_breakdown=lang_counts,
            scan_duration_seconds=scan_duration,
            model_used=model_used,
        )

    def save_report(self, report: ScanReport) -> dict:
        """Write JSON and Markdown reports to disk. Returns file paths."""
        base = REPORT_OUTPUT_DIR / report.scan_id
        base.mkdir(exist_ok=True)

        json_path = base / "report.json"
        md_path = base / "report.md"

        with open(json_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)

        with open(md_path, "w") as f:
            f.write(report.to_markdown())

        logger.info("Report saved: %s", base)
        return {"json": str(json_path), "markdown": str(md_path)}

    def _compute_cvss(self, severity: str, cwe_ids: List[str]) -> tuple:
        """
        Simplified CVSS 3.1 Base Score estimation from severity label.
        In production, each finding would have a full AV:AC:PR:UI:S:C:I:A vector.
        """
        score = SEVERITY_MAP.get(severity, 5.0)
        # Adjust for specific high-impact CWEs
        if "CWE-89" in cwe_ids:   score = max(score, 9.8)   # SQL injection
        if "CWE-22" in cwe_ids:   score = max(score, 7.5)   # Path traversal
        if "CWE-306" in cwe_ids:  score = max(score, 9.1)   # Missing auth
        if "CWE-287" in cwe_ids:  score = max(score, 8.8)   # Improper auth
        if "CWE-79" in cwe_ids:   score = max(score, 6.1)   # XSS

        vec = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if score >= 9.0 else \
              f"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" if score >= 7.0 else \
              f"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
        return round(score, 1), vec

    def _deduplicate(self, findings: List[EnrichedFinding]) -> List[EnrichedFinding]:
        """
        Deduplicate findings where same CWE appears in overlapping line ranges
        of the same file (from chunking overlap).
        """
        seen = set()
        result = []
        for ef in findings:
            f = ef.finding
            if not f.has_vulnerability:
                result.append(ef)
                continue
            key = (f.file_path, f.function_name, frozenset(f.cwe_ids))
            if key in seen:
                ef.deduplicated = True
                continue
            seen.add(key)
            result.append(ef)
        dedup_count = sum(1 for e in findings if e.deduplicated)
        if dedup_count:
            logger.info("Deduplicated %d overlapping findings", dedup_count)
        return result
