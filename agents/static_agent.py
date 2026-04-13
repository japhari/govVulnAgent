"""
Static Heuristics Agent — wraps Semgrep as a callable tool.

Returns structured per-file findings that act as fast-pass signals
for the Semantic Vulnerability Agent.
"""
import asyncio
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from config import SEMGREP_RULESETS, SEMGREP_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class StaticFinding:
    rule_id: str
    severity: str          # ERROR / WARNING / INFO
    message: str
    file_path: str
    start_line: int
    end_line: int
    cwe_ids: List[str]     # extracted from rule metadata
    owasp: Optional[str]

    def to_hint(self) -> str:
        """Compact hint string for the Semantic Agent prompt."""
        cwes = ", ".join(self.cwe_ids) if self.cwe_ids else "unknown"
        return (
            f"[Semgrep:{self.severity}] Line {self.start_line}: {self.message} "
            f"(Rule: {self.rule_id}, CWE: {cwes})"
        )


class StaticHeuristicsAgent:
    """
    Invokes Semgrep on source files and returns structured findings.
    Operates as a tool call within the ReAct loop.
    """

    def __init__(self):
        self._semgrep_available = self._check_semgrep()

    def _check_semgrep(self) -> bool:
        try:
            r = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                logger.info("Semgrep available: %s", r.stdout.strip())
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        logger.warning("Semgrep not found. Static heuristics agent disabled.")
        return False

    async def scan_file(self, file_path: str, language: str) -> List[StaticFinding]:
        """Async scan of a single file. Returns [] if Semgrep unavailable."""
        if not self._semgrep_available:
            return []
        rulesets = SEMGREP_RULESETS.get(language, ["p/owasp-top-ten"])
        # Run in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._run_semgrep, file_path, rulesets
        )

    def _run_semgrep(self, file_path: str, rulesets: List[str]) -> List[StaticFinding]:
        cmd = [
            "semgrep",
            "--json",
            "--no-git-ignore",
            "--timeout", str(SEMGREP_TIMEOUT),
        ]
        for rs in rulesets:
            cmd += ["--config", rs]
        cmd.append(file_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SEMGREP_TIMEOUT + 10,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out for %s", file_path)
            return []
        except Exception as e:
            logger.error("Semgrep execution error: %s", e)
            return []

        if result.returncode not in (0, 1):
            logger.warning("Semgrep non-zero exit %d: %s", result.returncode, result.stderr[:200])
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("Semgrep JSON parse error")
            return []

        findings = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            cwe_ids = self._extract_cwes(meta)
            owasp = meta.get("owasp", [None])[0] if meta.get("owasp") else None
            severity = r.get("extra", {}).get("severity", "WARNING").upper()
            findings.append(StaticFinding(
                rule_id=r.get("check_id", "unknown"),
                severity=severity,
                message=r.get("extra", {}).get("message", ""),
                file_path=r.get("path", file_path),
                start_line=r.get("start", {}).get("line", 0),
                end_line=r.get("end", {}).get("line", 0),
                cwe_ids=cwe_ids,
                owasp=owasp,
            ))

        logger.debug("Semgrep: %d findings in %s", len(findings), file_path)
        return findings

    def _extract_cwes(self, metadata: dict) -> List[str]:
        """Extract CWE IDs from Semgrep rule metadata."""
        cwes = []
        raw = metadata.get("cwe", [])
        if isinstance(raw, str):
            raw = [raw]
        for c in raw:
            if "CWE-" in str(c):
                import re
                matches = re.findall(r"CWE-\d+", str(c))
                cwes.extend(matches)
        return cwes

    def findings_for_chunk(
        self, findings: List[StaticFinding], start_line: int, end_line: int
    ) -> List[StaticFinding]:
        """Filter findings that overlap with a code chunk's line range."""
        return [
            f for f in findings
            if not (f.end_line < start_line or f.start_line > end_line)
        ]

    def hints_for_chunk(
        self, findings: List[StaticFinding], start_line: int, end_line: int
    ) -> str:
        """Return hint strings for the semantic agent prompt."""
        chunk_findings = self.findings_for_chunk(findings, start_line, end_line)
        if not chunk_findings:
            return "No static analysis findings for this chunk."
        return "\n".join(f.to_hint() for f in chunk_findings)
