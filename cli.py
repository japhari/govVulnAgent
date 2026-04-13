#!/usr/bin/env python3
"""
GovVulnAgent CLI — scan repositories or single files from the command line.

Usage:
    python cli.py scan /path/to/repo
    python cli.py scan /path/to/repo --pattern "**/*.java" --max-files 50
    python cli.py scan-file /path/to/file.java
    python cli.py status
    python cli.py build-index --nvd-dir ./data/nvd --cwe-xml ./data/cwe/cwec.xml
"""
import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("govvulnagent.cli")


async def cmd_scan(args):
    from agents.orchestrator import OrchestratorAgent
    orch = OrchestratorAgent()
    try:
        patterns = [args.pattern] if args.pattern else None
        report = await orch.scan_repository(
            repo_path=args.path,
            file_patterns=patterns,
            max_files=args.max_files,
        )
        print(f"\n{'='*60}")
        print(f"  GovVulnAgent Scan Complete — ID: {report.scan_id}")
        print(f"{'='*60}")
        print(f"  Files scanned:       {report.total_files_scanned}")
        print(f"  Chunks analyzed:     {report.total_chunks_analyzed}")
        print(f"  Vulnerabilities:     {report.total_vulnerabilities}")
        print(f"  Duration:            {report.scan_duration_seconds:.1f}s")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = report.findings_by_severity.get(sev, 0)
            if count:
                bar = "█" * min(count, 30)
                print(f"  {sev:<10} {count:>4}  {bar}")
        print(f"{'='*60}")
        print(f"  Report: reports/{report.scan_id}/")
        print()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"JSON report saved to: {args.output}")
    finally:
        await orch.close()


async def cmd_scan_file(args):
    from agents.orchestrator import OrchestratorAgent
    orch = OrchestratorAgent()
    try:
        report = await orch.scan_file(args.file)
        print(json.dumps(report.to_dict(), indent=2))
    finally:
        await orch.close()


async def cmd_status(args):
    from models.ollama_client import OllamaClient
    from agents.rag_agent import CVECWERAGAgent
    from agents.static_agent import StaticHeuristicsAgent
    client = OllamaClient()
    available = await client.is_available()
    model = await client.active_model() if available else "N/A"
    rag = CVECWERAGAgent()
    static = StaticHeuristicsAgent()
    print(f"\n  GovVulnAgent Status")
    print(f"  {'─'*30}")
    print(f"  Ollama:   {'✓ Running' if available else '✗ Not reachable'}")
    print(f"  Model:    {model}")
    print(f"  RAG:      {'✓ Index loaded' if rag.is_available() else '✗ Index not found (run build-index)'}")
    print(f"  Semgrep:  {'✓ Available' if static._semgrep_available else '✗ Not installed'}")
    print()
    await client.close()


def cmd_build_index(args):
    from agents.rag_agent import build_index_from_nvd
    try:
        build_index_from_nvd(
            nvd_dir=args.nvd_dir,
            cwe_xml_path=args.cwe_xml,
            output_dir="data/cwe",
        )
    except Exception as e:
        logger.error("Failed to build RAG index: %s", e)
        logger.error(
            "Expected input: --nvd-dir with NVD JSON feeds and --cwe-xml with MITRE CWE XML file."
        )
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="govvulnagent",
        description="GovVulnAgent — Sovereign Multi-Agent Code Vulnerability Scanner",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a repository or directory")
    p_scan.add_argument("path", help="Path to repository root")
    p_scan.add_argument("--pattern", help="File glob pattern, e.g. '**/*.java'")
    p_scan.add_argument("--max-files", type=int, default=None)
    p_scan.add_argument("--output", help="Save JSON report to file")

    # scan-file
    p_file = sub.add_parser("scan-file", help="Scan a single file")
    p_file.add_argument("file", help="Path to source file")

    # status
    sub.add_parser("status", help="Check Ollama, RAG, and Semgrep availability")

    # build-index
    p_idx = sub.add_parser("build-index", help="Build FAISS index from NVD JSON feeds")
    p_idx.add_argument("--nvd-dir", required=True, help="Directory with NVD annual JSON files")
    p_idx.add_argument("--cwe-xml", required=True, help="Path to MITRE CWE XML file")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(cmd_scan(args))
    elif args.command == "scan-file":
        asyncio.run(cmd_scan_file(args))
    elif args.command == "status":
        asyncio.run(cmd_status(args))
    elif args.command == "build-index":
        cmd_build_index(args)


if __name__ == "__main__":
    main()
