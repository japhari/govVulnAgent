"""
Code Parser Agent — extracts AST-based function/method chunks from source files.

Supports Java, JavaScript (JSX), TypeScript (TSX) via tree-sitter.
"""
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# tree-sitter node types per language that define a named callable unit
_FUNCTION_NODE_TYPES = {
    "java": {
        "method_declaration",
        "constructor_declaration",
        "static_initializer",
    },
    "javascript": {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    },
    "typescript": {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "method_signature",
    },
}

_PRIORITY_ANNOTATIONS = {
    "java": [
        "@RequestMapping", "@GetMapping", "@PostMapping", "@PutMapping",
        "@DeleteMapping", "@PatchMapping", "@PreAuthorize", "@Secured",
        "@Transactional", "@RestController", "@Controller",
    ],
    "javascript": [
        "onClick", "onSubmit", "onChange", "useEffect", "useCallback",
        "fetch(", "axios.", "XMLHttpRequest", "innerHTML", "dangerouslySetInnerHTML",
    ],
    "typescript": [
        "HttpClient", "@Injectable", "@Guard", "intercept(", "canActivate(",
        "this.http.", "@Component", "@Pipe",
    ],
}


@dataclass
class CodeChunk:
    file_path: str
    language: str
    function_name: str
    class_name: Optional[str]
    start_line: int
    end_line: int
    source: str
    annotations: List[str] = field(default_factory=list)
    is_priority: bool = False
    token_estimate: int = 0

    @property
    def chunk_id(self) -> str:
        return f"{self.file_path}::{self.class_name or '_'}::{self.function_name}:{self.start_line}"

    def summary(self) -> str:
        return (
            f"File: {self.file_path}\n"
            f"Language: {self.language}\n"
            f"Class: {self.class_name or 'N/A'}\n"
            f"Function: {self.function_name}\n"
            f"Lines: {self.start_line}–{self.end_line}\n"
            f"Annotations: {', '.join(self.annotations) or 'None'}\n"
        )


class CodeParserAgent:
    """
    Parses source files into CodeChunk objects using tree-sitter ASTs.

    Falls back to line-based chunking if tree-sitter grammars are unavailable.
    """

    def __init__(self):
        self._parsers = {}
        self._load_parsers()

    def _load_parsers(self):
        """Lazy-load tree-sitter parsers for each supported language."""
        try:
            import tree_sitter_java as tsjava
            import tree_sitter_javascript as tsjs
            import tree_sitter_typescript as tsts
            from tree_sitter import Language, Parser

            self._parsers["java"] = Parser(Language(tsjava.language()))
            self._parsers["javascript"] = Parser(Language(tsjs.language()))
            self._parsers["typescript"] = Parser(Language(tsts.language_typescript()))
            logger.info("tree-sitter parsers loaded for: %s", list(self._parsers.keys()))
        except ImportError as e:
            logger.warning(
                "tree-sitter grammars not installed (%s). Using line-based fallback.", e
            )

    def detect_language(self, file_path: str) -> Optional[str]:
        from config import SUPPORTED_LANGUAGES
        ext = Path(file_path).suffix.lower()
        return SUPPORTED_LANGUAGES.get(ext)

    def parse_file(self, file_path: str) -> List[CodeChunk]:
        """Parse a source file and return a list of CodeChunks."""
        from config import MAX_FILE_SIZE_KB

        path = Path(file_path)
        if not path.exists():
            logger.error("File not found: %s", file_path)
            return []

        size_kb = path.stat().st_size / 1024
        if size_kb > MAX_FILE_SIZE_KB:
            logger.warning("Skipping large file (%d KB): %s", int(size_kb), file_path)
            return []

        language = self.detect_language(file_path)
        if not language:
            logger.debug("Unsupported language for: %s", file_path)
            return []

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.error("Cannot read %s: %s", file_path, e)
            return []

        if language in self._parsers:
            return self._parse_ast(file_path, language, source)
        else:
            return self._parse_lines(file_path, language, source)

    def _parse_ast(self, file_path: str, language: str, source: str) -> List[CodeChunk]:
        """AST-based chunking using tree-sitter."""
        parser = self._parsers[language]
        tree = parser.parse(source.encode())
        lines = source.splitlines()

        chunks = []
        function_types = _FUNCTION_NODE_TYPES.get(language, set())

        def walk(node, current_class=None):
            # Track class context
            cls = current_class
            if node.type in ("class_declaration", "class_body", "interface_declaration"):
                cls = self._extract_name(node, lines)

            if node.type in function_types:
                name = self._extract_name(node, lines) or f"anonymous_{node.start_point[0]}"
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                func_source = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])

                # Extract annotations for Java
                annotations = []
                if language == "java":
                    annotations = self._extract_java_annotations(node, lines)

                chunk = CodeChunk(
                    file_path=file_path,
                    language=language,
                    function_name=name,
                    class_name=cls,
                    start_line=start_line,
                    end_line=end_line,
                    source=func_source,
                    annotations=annotations,
                    is_priority=self._is_priority(func_source, language, annotations),
                    token_estimate=len(func_source.split()) * 2,
                )
                chunks.append(chunk)

            for child in node.children:
                walk(child, cls)

        walk(tree.root_node)
        logger.debug("Parsed %d chunks from %s", len(chunks), file_path)
        return self._apply_chunking_limits(chunks)

    def _parse_lines(self, file_path: str, language: str, source: str) -> List[CodeChunk]:
        """Fallback: split by brace-balanced blocks (heuristic)."""
        from config import CHUNK_MAX_TOKENS
        lines = source.splitlines()
        chunks = []
        chunk_size = CHUNK_MAX_TOKENS * 4  # approx chars

        i = 0
        block_n = 0
        while i < len(lines):
            end = min(i + 60, len(lines))
            block = "\n".join(lines[i:end])
            block_n += 1
            chunk = CodeChunk(
                file_path=file_path,
                language=language,
                function_name=f"block_{block_n}",
                class_name=None,
                start_line=i + 1,
                end_line=end,
                source=block,
                is_priority=self._is_priority(block, language, []),
                token_estimate=len(block.split()) * 2,
            )
            chunks.append(chunk)
            i = end
        return chunks

    def _extract_name(self, node, lines) -> Optional[str]:
        """Extract the identifier name from a function/class node."""
        for child in node.children:
            if child.type == "identifier":
                start = child.start_point
                return lines[start[0]][start[1]:child.end_point[1]]
        return None

    def _extract_java_annotations(self, node, lines) -> List[str]:
        """Walk sibling nodes before a method to find annotations."""
        annotations = []
        try:
            parent = node.parent
            if parent:
                siblings = parent.children
                idx = next((i for i, c in enumerate(siblings) if c == node), None)
                if idx:
                    for sib in siblings[:idx]:
                        if sib.type == "modifiers":
                            text = lines[sib.start_point[0]][sib.start_point[1]:sib.end_point[1]]
                            for ann in _PRIORITY_ANNOTATIONS["java"]:
                                if ann in text:
                                    annotations.append(ann)
        except Exception:
            pass
        return annotations

    def _is_priority(self, source: str, language: str, annotations: List[str]) -> bool:
        """Mark a chunk as high-priority based on security-relevant patterns."""
        if annotations:
            return True
        patterns = _PRIORITY_ANNOTATIONS.get(language, [])
        return any(p in source for p in patterns)

    def _apply_chunking_limits(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Split chunks that exceed token limit with overlap."""
        from config import CHUNK_MAX_TOKENS, CHUNK_OVERLAP_TOKENS
        result = []
        for chunk in chunks:
            if chunk.token_estimate <= CHUNK_MAX_TOKENS * 4:
                result.append(chunk)
            else:
                # Split large functions into sub-chunks
                src_lines = chunk.source.splitlines()
                step = 50
                for i in range(0, len(src_lines), step - 5):
                    sub_src = "\n".join(src_lines[i:i + step])
                    sub = CodeChunk(
                        file_path=chunk.file_path,
                        language=chunk.language,
                        function_name=f"{chunk.function_name}__part{i // step}",
                        class_name=chunk.class_name,
                        start_line=chunk.start_line + i,
                        end_line=chunk.start_line + min(i + step, len(src_lines)),
                        source=sub_src,
                        annotations=chunk.annotations,
                        is_priority=chunk.is_priority,
                        token_estimate=len(sub_src.split()) * 2,
                    )
                    result.append(sub)
        return result
