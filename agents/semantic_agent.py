"""
Semantic Vulnerability Agent — uses Qwen2.5-Coder-32B via Ollama
to perform deep chain-of-thought vulnerability analysis on code chunks.
"""
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from agents.parser_agent import CodeChunk
from models.ollama_client import OllamaClient

logger = logging.getLogger(__name__)


@dataclass
class SemanticFinding:
    chunk_id: str
    file_path: str
    language: str
    function_name: str
    start_line: int
    end_line: int
    has_vulnerability: bool
    cwe_ids: List[str]
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float      # 0.0–1.0
    reasoning: str
    raw_source: str
    static_hints: str = ""

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "file_path": self.file_path,
            "language": self.language,
            "function_name": self.function_name,
            "lines": f"{self.start_line}-{self.end_line}",
            "has_vulnerability": self.has_vulnerability,
            "cwe_ids": self.cwe_ids,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


# ── System prompt ─────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """You are an expert secure code reviewer specializing in identifying security vulnerabilities in government information system codebases. You have deep knowledge of:
- OWASP Top 10 (2021)
- NIST CWE Common Weakness Enumeration
- CVSS 3.1 severity scoring
- Language-specific vulnerability patterns (Java Spring Boot, React/JavaScript, Angular/TypeScript)

Your task is to analyze a code chunk and return a JSON object ONLY — no prose, no markdown, no explanation outside the JSON.

Required JSON schema:
{
  "has_vulnerability": <boolean>,
  "cwe_ids": [<list of CWE-NNN strings, empty if no vulnerability>],
  "description": "<concise description of the vulnerability, or 'No vulnerability detected'>",
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "confidence": <float 0.0-1.0>,
  "reasoning": "<step-by-step chain-of-thought: (1) data flow analysis, (2) trust boundary check, (3) input validation assessment, (4) verdict>"
}

IMPORTANT: Return ONLY valid JSON. No backticks. No preamble."""

# ── Few-shot examples per language ────────────────────────────────────────────
_FEW_SHOT = {
    "java": """
EXAMPLE 1 — Vulnerable Java (SQL Injection):
```java
public User findUser(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, userRowMapper);
}
```
Static hints: [Semgrep:ERROR] Line 2: SQL injection via string concatenation (CWE-89)
Expected JSON:
{"has_vulnerability":true,"cwe_ids":["CWE-89"],"description":"Direct string concatenation in SQL query allows SQL injection. User-supplied 'username' is concatenated without sanitization.","severity":"CRITICAL","confidence":0.98,"reasoning":"(1) Data flow: username parameter flows directly into SQL string. (2) Trust boundary: username is external user input. (3) Input validation: no parameterization, no escaping. (4) Verdict: SQL injection vulnerability present."}

EXAMPLE 2 — Clean Java:
```java
public User findUser(String username) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM users WHERE username = ?",
        new Object[]{username}, userRowMapper);
}
```
Static hints: No static analysis findings for this chunk.
Expected JSON:
{"has_vulnerability":false,"cwe_ids":[],"description":"No vulnerability detected","severity":"INFO","confidence":0.95,"reasoning":"(1) Data flow: username is passed as a parameterized argument. (2) Trust boundary: properly isolated via PreparedStatement-equivalent. (3) Input validation: parameterization prevents injection. (4) Verdict: No vulnerability."}
""",

    "javascript": """
EXAMPLE 1 — Vulnerable JS (XSS):
```javascript
function renderComment(comment) {
    document.getElementById('output').innerHTML = comment;
}
```
Static hints: [Semgrep:ERROR] Line 2: Cross-site scripting via innerHTML assignment (CWE-79)
Expected JSON:
{"has_vulnerability":true,"cwe_ids":["CWE-79"],"description":"Unescaped user-controlled content assigned to innerHTML allows XSS. Malicious script tags in 'comment' will execute in victim's browser.","severity":"HIGH","confidence":0.97,"reasoning":"(1) Data flow: comment flows directly to innerHTML. (2) Trust boundary: comment is user-supplied external data. (3) Input validation: no HTML encoding or sanitization. (4) Verdict: Reflected/stored XSS vulnerability."}

EXAMPLE 2 — Clean JS:
```javascript
function renderComment(comment) {
    const el = document.createElement('p');
    el.textContent = comment;
    document.getElementById('output').appendChild(el);
}
```
Static hints: No static analysis findings for this chunk.
Expected JSON:
{"has_vulnerability":false,"cwe_ids":[],"description":"No vulnerability detected","severity":"INFO","confidence":0.96,"reasoning":"(1) Data flow: comment is set via textContent which auto-escapes HTML. (2) Trust boundary: properly handled. (3) Input validation: textContent prevents script execution. (4) Verdict: No XSS vulnerability."}
""",

    "typescript": """
EXAMPLE 1 — Vulnerable TypeScript (Missing auth guard):
```typescript
@Get('/admin/users')
async getAllUsers(): Promise<User[]> {
    return this.userService.findAll();
}
```
Static hints: No static analysis findings for this chunk.
Expected JSON:
{"has_vulnerability":true,"cwe_ids":["CWE-306","CWE-285"],"description":"Admin endpoint exposes all users without authentication or authorization decorator. Missing @UseGuards() allows unauthenticated access.","severity":"HIGH","confidence":0.89,"reasoning":"(1) Data flow: returns full user list. (2) Trust boundary: no @UseGuards, @Roles, or @PreAuthorize applied. (3) Input validation: N/A. (4) Verdict: Missing authentication check on privileged endpoint."}
""",
}


class SemanticVulnerabilityAgent:
    """
    Uses chain-of-thought prompting with Qwen2.5-Coder to detect
    semantic vulnerabilities in code chunks.
    """

    def __init__(self, ollama: OllamaClient):
        self.ollama = ollama

    async def analyze_chunk(
        self,
        chunk: CodeChunk,
        static_hints: str = "",
    ) -> SemanticFinding:
        """Analyze a single code chunk. Returns a SemanticFinding."""
        prompt = self._build_prompt(chunk, static_hints)

        try:
            result = await self.ollama.generate_json(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
            )
        except Exception as e:
            logger.error("LLM analysis failed for %s: %s", chunk.chunk_id, e)
            return self._error_finding(chunk, str(e))

        return self._parse_result(chunk, result, static_hints)

    async def analyze_chunks_batch(
        self,
        chunks: List[CodeChunk],
        static_hints_map: dict,  # chunk_id -> hint string
        max_concurrent: int = 3,
    ) -> List[SemanticFinding]:
        """Analyze multiple chunks with limited concurrency."""
        import asyncio

        semaphore = asyncio.Semaphore(max_concurrent)

        async def bounded_analyze(chunk):
            async with semaphore:
                hints = static_hints_map.get(chunk.chunk_id, "")
                return await self.analyze_chunk(chunk, hints)

        results = await asyncio.gather(*[bounded_analyze(c) for c in chunks])
        return list(results)

    def _build_prompt(self, chunk: CodeChunk, static_hints: str) -> str:
        few_shot = _FEW_SHOT.get(chunk.language, "")
        return f"""{few_shot}

Now analyze this {chunk.language.upper()} code chunk:

{chunk.summary()}
```{chunk.language}
{chunk.source}
```

Static analysis hints:
{static_hints or "No static analysis findings for this chunk."}

Return JSON only:"""

    def _parse_result(
        self, chunk: CodeChunk, result: dict, static_hints: str
    ) -> SemanticFinding:
        if not result:
            return self._error_finding(chunk, "Empty LLM response")

        cwe_ids = result.get("cwe_ids", [])
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids] if cwe_ids else []

        return SemanticFinding(
            chunk_id=chunk.chunk_id,
            file_path=chunk.file_path,
            language=chunk.language,
            function_name=chunk.function_name,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            has_vulnerability=bool(result.get("has_vulnerability", False)),
            cwe_ids=cwe_ids,
            description=result.get("description", ""),
            severity=result.get("severity", "INFO").upper(),
            confidence=float(result.get("confidence", 0.5)),
            reasoning=result.get("reasoning", ""),
            raw_source=chunk.source,
            static_hints=static_hints,
        )

    def _error_finding(self, chunk: CodeChunk, error: str) -> SemanticFinding:
        return SemanticFinding(
            chunk_id=chunk.chunk_id,
            file_path=chunk.file_path,
            language=chunk.language,
            function_name=chunk.function_name,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            has_vulnerability=False,
            cwe_ids=[],
            description=f"Analysis error: {error}",
            severity="INFO",
            confidence=0.0,
            reasoning="Analysis failed due to LLM error.",
            raw_source=chunk.source,
        )
