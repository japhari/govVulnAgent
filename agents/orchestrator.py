"""
Orchestrator Agent — drives the full GovVulnAgent multi-agent pipeline.

ReAct loop:
  Thought: what files to scan, which agents to invoke
  Action: invoke Code Parser → Static Heuristics → Semantic Vuln → RAG → Report
  Observation: findings per file
  Final Output: consolidated ScanReport
"""
import asyncio
import logging
import time
import uuid
from pathlib import Path
from typing import List, Optional

from agents.parser_agent import CodeParserAgent, CodeChunk
from agents.static_agent import StaticHeuristicsAgent, StaticFinding
from agents.semantic_agent import SemanticVulnerabilityAgent, SemanticFinding
from agents.rag_agent import CVECWERAGAgent, RAGResult
from agents.report_agent import ReportAgent, ScanReport
from models.ollama_client import OllamaClient
from config import SUPPORTED_LANGUAGES

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """
    Main entry point for GovVulnAgent. Coordinates all sub-agents.
    """

    def __init__(self):
        self.ollama = OllamaClient()
        self.parser = CodeParserAgent()
        self.static = StaticHeuristicsAgent()
        self.semantic = SemanticVulnerabilityAgent(self.ollama)
        self.rag = CVECWERAGAgent()
        self.reporter = ReportAgent()

    async def scan_repository(
        self,
        repo_path: str,
        file_patterns: Optional[List[str]] = None,
        max_files: Optional[int] = None,
    ) -> ScanReport:
        """
        Full pipeline scan of a repository or directory.

        Args:
            repo_path: Path to repository root
            file_patterns: Optional list of glob patterns (e.g. ["**/*.java"])
            max_files: Optional cap on files to scan (for testing)

        Returns:
            ScanReport with all findings
        """
        scan_id = str(uuid.uuid4())[:8]
        start_time = time.monotonic()
        logger.info("=== GovVulnAgent Scan START [%s] repo=%s ===", scan_id, repo_path)

        # ── Step 1: Enumerate source files ───────────────────────────────────
        source_files = self._enumerate_files(repo_path, file_patterns, max_files)
        logger.info("Found %d source files to scan", len(source_files))

        all_chunks: List[CodeChunk] = []
        all_static: dict = {}         # file_path -> List[StaticFinding]
        all_semantic: List[SemanticFinding] = []
        rag_map: dict = {}             # chunk_id -> List[RAGResult]

        # ── Step 2: Parse + Static Scan (per file) ────────────────────────────
        for file_path in source_files:
            language = self.parser.detect_language(file_path)
            if not language:
                continue

            # THOUGHT: Parse this file into chunks
            chunks = self.parser.parse_file(file_path)
            if not chunks:
                continue
            all_chunks.extend(chunks)

            # ACTION: Run static analysis on this file
            static_findings = await self.static.scan_file(file_path, language)
            all_static[file_path] = static_findings
            logger.debug("File %s: %d chunks, %d static findings", file_path, len(chunks), len(static_findings))

        logger.info("Total chunks to analyze: %d", len(all_chunks))

        # ── Step 3: Semantic Analysis (batched) ───────────────────────────────
        # Build hints map: chunk_id -> hint string from static findings
        hints_map = {}
        for chunk in all_chunks:
            static = all_static.get(chunk.file_path, [])
            hints_map[chunk.chunk_id] = self.static.hints_for_chunk(
                static, chunk.start_line, chunk.end_line
            )

        # Prioritize chunks flagged by static analysis or heuristics
        priority_chunks = [c for c in all_chunks if c.is_priority]
        normal_chunks = [c for c in all_chunks if not c.is_priority]
        ordered_chunks = priority_chunks + normal_chunks

        # THOUGHT: Run semantic analysis with limited concurrency to avoid OOM
        logger.info("Starting semantic analysis (%d priority + %d normal chunks)...",
                    len(priority_chunks), len(normal_chunks))
        semantic_findings = await self.semantic.analyze_chunks_batch(
            ordered_chunks,
            static_hints_map=hints_map,
            max_concurrent=3,
        )
        all_semantic.extend(semantic_findings)

        # ── Step 4: RAG Enrichment (only for positive findings) ───────────────
        vuln_findings = [f for f in all_semantic if f.has_vulnerability]
        logger.info("Enriching %d vulnerability findings via RAG...", len(vuln_findings))

        for finding in vuln_findings:
            rag_results = await self.rag.retrieve(
                finding.description, finding.cwe_ids
            )
            rag_map[finding.chunk_id] = rag_results

        # ── Step 5: Generate Report ───────────────────────────────────────────
        model_used = await self.ollama.active_model()
        duration = time.monotonic() - start_time

        report = self.reporter.build_report(
            scan_id=scan_id,
            repository_path=repo_path,
            findings=all_semantic,
            rag_map=rag_map,
            total_files=len(source_files),
            total_chunks=len(all_chunks),
            scan_duration=duration,
            model_used=model_used,
        )

        paths = self.reporter.save_report(report)
        logger.info(
            "=== GovVulnAgent Scan COMPLETE [%s] — %d vulns in %.1fs ===",
            scan_id, report.total_vulnerabilities, duration,
        )
        logger.info("Report: %s", paths)
        return report

    async def scan_file(self, file_path: str) -> ScanReport:
        """Convenience method to scan a single file."""
        return await self.scan_repository(
            repo_path=str(Path(file_path).parent),
            file_patterns=[Path(file_path).name],
        )

    def _enumerate_files(
        self,
        repo_path: str,
        file_patterns: Optional[List[str]],
        max_files: Optional[int],
    ) -> List[str]:
        """Walk directory and collect all supported source files."""
        root = Path(repo_path)
        if not root.exists():
            logger.error("Repository path does not exist: %s", repo_path)
            return []

        files = []
        extensions = set(SUPPORTED_LANGUAGES.keys())

        SKIP_DIRS = {
            ".git", "node_modules", "__pycache__", ".gradle", "build",
            "dist", "target", ".next", ".nuxt", "out", "coverage",
            "vendor", ".mvn", "test", "tests", "__tests__",
        }

        if file_patterns:
            for pattern in file_patterns:
                files.extend(str(p) for p in root.glob(pattern))
        else:
            for path in root.rglob("*"):
                if any(skip in path.parts for skip in SKIP_DIRS):
                    continue
                if path.suffix.lower() in extensions:
                    files.append(str(path))

        files = sorted(set(files))
        if max_files:
            files = files[:max_files]
        return files

    async def close(self):
        await self.ollama.close()
