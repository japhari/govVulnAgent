"""
GovVulnAgent — FastAPI REST API

Endpoints:
  POST /scan      — scan a repository path
  POST /scan/file — scan a single file (upload or path)
  GET  /report/{scan_id} — retrieve a past report
  GET  /status    — health check and model status
"""
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.orchestrator import OrchestratorAgent
from config import API_HOST, API_PORT, REPORT_OUTPUT_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("govvulnagent.api")

# ── Global orchestrator (singleton) ──────────────────────────────────────────
_orchestrator: Optional[OrchestratorAgent] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _orchestrator
    logger.info("Initializing GovVulnAgent...")
    _orchestrator = OrchestratorAgent()
    available = await _orchestrator.ollama.is_available()
    if not available:
        logger.warning("Ollama not reachable. Ensure Ollama is running: ollama serve")
    else:
        model = await _orchestrator.ollama.active_model()
        logger.info("Active model: %s", model)
    yield
    if _orchestrator:
        await _orchestrator.close()
    logger.info("GovVulnAgent shutdown complete.")


app = FastAPI(
    title="GovVulnAgent",
    description="Sovereign Multi-Agent LLM Framework for Government Code Vulnerability Detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request/Response Models ───────────────────────────────────────────────────
class ScanRequest(BaseModel):
    repository_path: str = Field(..., description="Absolute path to repository")
    file_patterns: Optional[List[str]] = Field(
        None, description="Glob patterns to filter files, e.g. ['**/*.java']"
    )
    max_files: Optional[int] = Field(
        None, description="Maximum number of files to scan (for testing)"
    )


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    message: str


# ── Active Scans Tracker ──────────────────────────────────────────────────────
_active_scans: dict = {}
_completed_scans: dict = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/status")
async def health_check():
    """Health check and Ollama model status."""
    if not _orchestrator:
        return {"status": "initializing"}
    available = await _orchestrator.ollama.is_available()
    model = await _orchestrator.ollama.active_model() if available else None
    rag_available = _orchestrator.rag.is_available()
    semgrep_available = _orchestrator.static._semgrep_available
    return {
        "status": "ok" if available else "degraded",
        "ollama": available,
        "model": model,
        "rag_available": rag_available,
        "semgrep_available": semgrep_available,
        "version": "1.0.0",
    }


@app.post("/scan", response_model=ScanStatus)
async def scan_repository(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start an asynchronous scan of a repository.
    Returns a scan_id; poll /report/{scan_id} for results.
    """
    if not _orchestrator:
        raise HTTPException(503, "Agent not initialized")

    repo = Path(request.repository_path)
    if not repo.exists():
        raise HTTPException(400, f"Repository path does not exist: {request.repository_path}")

    # Generate a scan ID and start background task
    import uuid
    scan_id = str(uuid.uuid4())[:8]
    _active_scans[scan_id] = {"status": "running", "path": str(repo)}

    async def run_scan():
        try:
            report = await _orchestrator.scan_repository(
                repo_path=str(repo),
                file_patterns=request.file_patterns,
                max_files=request.max_files,
            )
            _completed_scans[scan_id] = report.to_dict()
            _active_scans[scan_id]["status"] = "complete"
            logger.info("Scan %s complete: %d vulnerabilities", scan_id, report.total_vulnerabilities)
        except Exception as e:
            logger.error("Scan %s failed: %s", scan_id, e)
            _active_scans[scan_id] = {"status": "error", "error": str(e)}

    background_tasks.add_task(run_scan)
    return ScanStatus(
        scan_id=scan_id,
        status="running",
        message=f"Scan started. Poll GET /report/{scan_id} for results.",
    )


@app.post("/scan/sync")
async def scan_repository_sync(request: ScanRequest):
    """
    Synchronous scan (blocks until complete). Use for small repos or single files.
    """
    if not _orchestrator:
        raise HTTPException(503, "Agent not initialized")

    repo = Path(request.repository_path)
    if not repo.exists():
        raise HTTPException(400, f"Repository path does not exist: {request.repository_path}")

    try:
        report = await _orchestrator.scan_repository(
            repo_path=str(repo),
            file_patterns=request.file_patterns,
            max_files=request.max_files,
        )
        return JSONResponse(content=report.to_dict())
    except Exception as e:
        logger.exception("Synchronous scan failed")
        raise HTTPException(500, str(e))


@app.post("/scan/file")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """
    Scan an uploaded source file directly.
    """
    if not _orchestrator:
        raise HTTPException(503, "Agent not initialized")

    import tempfile
    suffix = Path(file.filename).suffix if file.filename else ".java"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        report = await _orchestrator.scan_file(tmp_path)
        return JSONResponse(content=report.to_dict())
    finally:
        os.unlink(tmp_path)


@app.get("/report/{scan_id}")
async def get_report(scan_id: str, format: str = "json"):
    """
    Retrieve scan results. format=json (default) or format=markdown.
    """
    # Check in-memory
    if scan_id in _active_scans:
        status = _active_scans[scan_id]
        if status.get("status") == "running":
            return {"scan_id": scan_id, "status": "running"}
        if status.get("status") == "error":
            raise HTTPException(500, status.get("error", "Scan failed"))

    if scan_id in _completed_scans:
        return JSONResponse(content=_completed_scans[scan_id])

    # Check disk
    report_dir = REPORT_OUTPUT_DIR / scan_id
    if format == "markdown":
        md_path = report_dir / "report.md"
        if md_path.exists():
            return {"markdown": md_path.read_text()}
    else:
        json_path = report_dir / "report.json"
        if json_path.exists():
            import json
            return JSONResponse(content=json.loads(json_path.read_text()))

    raise HTTPException(404, f"Report {scan_id} not found")


@app.get("/reports")
async def list_reports():
    """List all available scan reports on disk."""
    reports = []
    for d in sorted(REPORT_OUTPUT_DIR.iterdir()):
        if d.is_dir():
            json_path = d / "report.json"
            if json_path.exists():
                import json
                try:
                    data = json.loads(json_path.read_text())
                    reports.append({
                        "scan_id": data.get("scan_id"),
                        "timestamp": data.get("scan_timestamp"),
                        "repository": data.get("repository_path"),
                        "vulnerabilities": data.get("summary", {}).get("total_vulnerabilities", 0),
                    })
                except Exception:
                    pass
    return {"reports": reports}


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=API_HOST,
        port=API_PORT,
        reload=False,
        workers=1,
    )
