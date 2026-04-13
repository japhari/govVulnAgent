"""
GovVulnAgent Test Suite

Run: pytest tests/ -v
"""
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Fixtures ─────────────────────────────────────────────────────────────────
VULN_JAVA = """
public class UserDao {
    public User findUser(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForObject(sql, userRowMapper);
    }
}
"""

CLEAN_JAVA = """
public class UserDao {
    public User findUser(String username) {
        return jdbcTemplate.queryForObject(
            "SELECT * FROM users WHERE username = ?",
            new Object[]{username}, userRowMapper
        );
    }
}
"""

VULN_JS = """
function renderUserInput(input) {
    document.getElementById('content').innerHTML = input;
}
"""

CLEAN_JS = """
function renderUserInput(input) {
    const el = document.createElement('p');
    el.textContent = input;
    document.getElementById('content').appendChild(el);
}
"""

VULN_TS = """
import { Component } from '@angular/core';

@Component({ selector: 'app-admin' })
export class AdminComponent {
    getAllUsers() {
        return this.http.get('/api/admin/users');
    }
}
"""


@pytest.fixture
def java_vuln_file(tmp_path):
    f = tmp_path / "UserDao.java"
    f.write_text(VULN_JAVA)
    return str(f)


@pytest.fixture
def java_clean_file(tmp_path):
    f = tmp_path / "UserDaoClean.java"
    f.write_text(CLEAN_JAVA)
    return str(f)


@pytest.fixture
def js_vuln_file(tmp_path):
    f = tmp_path / "render.js"
    f.write_text(VULN_JS)
    return str(f)


@pytest.fixture
def ts_vuln_file(tmp_path):
    f = tmp_path / "admin.component.ts"
    f.write_text(VULN_TS)
    return str(f)


# ── Code Parser Tests ─────────────────────────────────────────────────────────
class TestCodeParserAgent:

    def test_detect_language_java(self):
        from agents.parser_agent import CodeParserAgent
        agent = CodeParserAgent()
        assert agent.detect_language("Foo.java") == "java"
        assert agent.detect_language("bar.jsx") == "javascript"
        assert agent.detect_language("baz.ts") == "typescript"
        assert agent.detect_language("readme.md") is None

    def test_parse_java_file(self, java_vuln_file):
        from agents.parser_agent import CodeParserAgent
        agent = CodeParserAgent()
        chunks = agent.parse_file(java_vuln_file)
        assert len(chunks) > 0
        chunk = chunks[0]
        assert chunk.language == "java"
        assert "findUser" in chunk.function_name or chunk.source
        assert chunk.start_line >= 1

    def test_parse_js_file(self, js_vuln_file):
        from agents.parser_agent import CodeParserAgent
        agent = CodeParserAgent()
        chunks = agent.parse_file(js_vuln_file)
        assert len(chunks) > 0

    def test_skip_nonexistent_file(self):
        from agents.parser_agent import CodeParserAgent
        agent = CodeParserAgent()
        chunks = agent.parse_file("/nonexistent/path/Foo.java")
        assert chunks == []

    def test_priority_detection_innerHTML(self, js_vuln_file):
        from agents.parser_agent import CodeParserAgent
        agent = CodeParserAgent()
        chunks = agent.parse_file(js_vuln_file)
        # innerHTML is a priority pattern
        assert any(c.is_priority for c in chunks)

    def test_chunk_id_format(self, java_vuln_file):
        from agents.parser_agent import CodeParserAgent
        agent = CodeParserAgent()
        chunks = agent.parse_file(java_vuln_file)
        if chunks:
            assert "::" in chunks[0].chunk_id


# ── Static Heuristics Tests ───────────────────────────────────────────────────
class TestStaticHeuristicsAgent:

    def test_extract_cwes(self):
        from agents.static_agent import StaticHeuristicsAgent
        agent = StaticHeuristicsAgent()
        meta = {"cwe": ["CWE-89: SQL Injection", "CWE-79"]}
        cwes = agent._extract_cwes(meta)
        assert "CWE-89" in cwes
        assert "CWE-79" in cwes

    def test_findings_for_chunk(self):
        from agents.static_agent import StaticHeuristicsAgent, StaticFinding
        agent = StaticHeuristicsAgent()
        findings = [
            StaticFinding("rule1", "ERROR", "SQL Injection", "f.java", 10, 15, ["CWE-89"], None),
            StaticFinding("rule2", "WARNING", "XSS", "f.java", 50, 55, ["CWE-79"], None),
        ]
        result = agent.findings_for_chunk(findings, start_line=8, end_line=20)
        assert len(result) == 1
        assert result[0].rule_id == "rule1"

    def test_hints_for_chunk_no_findings(self):
        from agents.static_agent import StaticHeuristicsAgent
        agent = StaticHeuristicsAgent()
        hints = agent.hints_for_chunk([], 1, 50)
        assert "No static analysis" in hints


# ── Semantic Agent Tests ──────────────────────────────────────────────────────
class TestSemanticVulnerabilityAgent:

    @pytest.mark.asyncio
    async def test_analyze_vuln_chunk(self, java_vuln_file):
        from agents.parser_agent import CodeParserAgent
        from agents.semantic_agent import SemanticVulnerabilityAgent
        from models.ollama_client import OllamaClient

        # Mock Ollama response
        mock_ollama = MagicMock()
        mock_ollama.generate_json = AsyncMock(return_value={
            "has_vulnerability": True,
            "cwe_ids": ["CWE-89"],
            "description": "SQL injection via string concatenation",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "reasoning": "Direct string concatenation in SQL query.",
        })

        parser = CodeParserAgent()
        chunks = parser.parse_file(java_vuln_file)

        agent = SemanticVulnerabilityAgent(mock_ollama)
        if chunks:
            finding = await agent.analyze_chunk(chunks[0], "Semgrep: SQL injection hint")
            assert finding.has_vulnerability is True
            assert "CWE-89" in finding.cwe_ids
            assert finding.severity == "CRITICAL"
            assert finding.confidence == 0.98

    @pytest.mark.asyncio
    async def test_analyze_clean_chunk(self, java_clean_file):
        from agents.parser_agent import CodeParserAgent
        from agents.semantic_agent import SemanticVulnerabilityAgent

        mock_ollama = MagicMock()
        mock_ollama.generate_json = AsyncMock(return_value={
            "has_vulnerability": False,
            "cwe_ids": [],
            "description": "No vulnerability detected",
            "severity": "INFO",
            "confidence": 0.95,
            "reasoning": "Parameterized query used.",
        })

        parser = CodeParserAgent()
        chunks = parser.parse_file(java_clean_file)

        agent = SemanticVulnerabilityAgent(mock_ollama)
        if chunks:
            finding = await agent.analyze_chunk(chunks[0])
            assert finding.has_vulnerability is False
            assert finding.cwe_ids == []

    @pytest.mark.asyncio
    async def test_llm_error_returns_safe_finding(self):
        from agents.parser_agent import CodeChunk
        from agents.semantic_agent import SemanticVulnerabilityAgent

        mock_ollama = MagicMock()
        mock_ollama.generate_json = AsyncMock(side_effect=Exception("Ollama timeout"))

        agent = SemanticVulnerabilityAgent(mock_ollama)
        chunk = CodeChunk("f.java", "java", "testFn", None, 1, 10, "void test(){}")
        finding = await agent.analyze_chunk(chunk)

        assert finding.has_vulnerability is False
        assert finding.confidence == 0.0
        assert "error" in finding.description.lower()


# ── RAG Agent Tests ───────────────────────────────────────────────────────────
class TestCVECWERAGAgent:

    def test_fallback_lookup_cwe89(self):
        from agents.rag_agent import CVECWERAGAgent
        agent = CVECWERAGAgent()  # FAISS likely not present in test env
        results = agent._fallback_lookup(["CWE-89"])
        assert len(results) == 1
        assert results[0].cwe_id == "CWE-89"
        assert "SQL" in results[0].cwe_name
        assert results[0].remediation

    def test_fallback_lookup_unknown_cwe(self):
        from agents.rag_agent import CVECWERAGAgent
        agent = CVECWERAGAgent()
        results = agent._fallback_lookup(["CWE-9999"])
        assert results == []

    @pytest.mark.asyncio
    async def test_retrieve_uses_fallback_when_unavailable(self):
        from agents.rag_agent import CVECWERAGAgent
        agent = CVECWERAGAgent()
        if not agent.is_available():
            results = await agent.retrieve("SQL injection via concat", ["CWE-89"])
            assert any(r.cwe_id == "CWE-89" for r in results)


# ── Report Agent Tests ────────────────────────────────────────────────────────
class TestReportAgent:

    def _make_finding(self, vuln=True, cwe="CWE-89", severity="HIGH"):
        from agents.semantic_agent import SemanticFinding
        return SemanticFinding(
            chunk_id="test.java::Foo::bar:1",
            file_path="test.java",
            language="java",
            function_name="bar",
            start_line=1,
            end_line=20,
            has_vulnerability=vuln,
            cwe_ids=[cwe] if vuln else [],
            description="SQL injection" if vuln else "Clean",
            severity=severity,
            confidence=0.95 if vuln else 0.90,
            reasoning="Test reasoning",
            raw_source="void bar(){}",
        )

    def test_build_report_structure(self, tmp_path):
        from agents.report_agent import ReportAgent
        from config import REPORT_OUTPUT_DIR
        agent = ReportAgent()
        findings = [
            self._make_finding(vuln=True),
            self._make_finding(vuln=False),
        ]
        report = agent.build_report(
            scan_id="test01",
            repository_path="/repo",
            findings=findings,
            rag_map={},
            total_files=1,
            total_chunks=2,
            scan_duration=3.5,
            model_used="qwen2.5-coder:32b",
        )
        assert report.total_vulnerabilities == 1
        assert report.scan_id == "test01"
        assert "HIGH" in report.findings_by_severity

    def test_cvss_sql_injection(self):
        from agents.report_agent import ReportAgent
        agent = ReportAgent()
        score, vec = agent._compute_cvss("CRITICAL", ["CWE-89"])
        assert score >= 9.0

    def test_cvss_xss(self):
        from agents.report_agent import ReportAgent
        agent = ReportAgent()
        score, vec = agent._compute_cvss("HIGH", ["CWE-79"])
        assert score >= 6.1

    def test_deduplication(self):
        from agents.report_agent import ReportAgent, EnrichedFinding
        agent = ReportAgent()
        f1 = self._make_finding()
        f2 = self._make_finding()  # Same chunk_id and CWE
        ef1 = EnrichedFinding(f1, [], 7.0, "CVSS:3.1/AV:N")
        ef2 = EnrichedFinding(f2, [], 7.0, "CVSS:3.1/AV:N")
        result = agent._deduplicate([ef1, ef2])
        non_dedup = [e for e in result if not e.deduplicated]
        assert len(non_dedup) == 1

    def test_markdown_report_generation(self):
        from agents.report_agent import ReportAgent
        agent = ReportAgent()
        findings = [self._make_finding(vuln=True, cwe="CWE-89", severity="CRITICAL")]
        report = agent.build_report(
            scan_id="mdtest",
            repository_path="/repo",
            findings=findings,
            rag_map={},
            total_files=1,
            total_chunks=1,
            scan_duration=1.0,
            model_used="qwen2.5-coder:32b",
        )
        md = report.to_markdown()
        assert "GovVulnAgent" in md
        assert "CWE-89" in md
        assert "CRITICAL" in md


# ── Integration Test ──────────────────────────────────────────────────────────
class TestIntegration:

    @pytest.mark.asyncio
    async def test_full_pipeline_mocked(self, java_vuln_file):
        """End-to-end pipeline test with mocked Ollama."""
        from agents.orchestrator import OrchestratorAgent
        from pathlib import Path

        # Patch Ollama to avoid requiring a running instance
        with patch("models.ollama_client.OllamaClient.is_available", new_callable=AsyncMock, return_value=True), \
             patch("models.ollama_client.OllamaClient.active_model", new_callable=AsyncMock, return_value="qwen2.5-coder:32b"), \
             patch("models.ollama_client.OllamaClient.generate_json", new_callable=AsyncMock, return_value={
                 "has_vulnerability": True,
                 "cwe_ids": ["CWE-89"],
                 "description": "SQL Injection",
                 "severity": "CRITICAL",
                 "confidence": 0.97,
                 "reasoning": "String concatenation in SQL query.",
             }):

            orch = OrchestratorAgent()
            repo_dir = str(Path(java_vuln_file).parent)
            report = await orch.scan_repository(
                repo_path=repo_dir,
                file_patterns=["*.java"],
            )
            assert report.total_files_scanned >= 1
            assert report.total_chunks_analyzed >= 0
            assert isinstance(report.total_vulnerabilities, int)
            await orch.close()
