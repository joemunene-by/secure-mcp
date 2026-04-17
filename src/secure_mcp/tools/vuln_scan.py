"""Static scan of a source tree for secrets and insecure patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


NAME = "vuln_scan"

# Pattern name -> regex. Kept conservative to limit false positives.
PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws.{0,20}(secret|key).{0,5}['\"][0-9a-zA-Z/+=]{40}['\"]"),
    "github_token": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
    "github_oauth": re.compile(r"\bgho_[0-9a-zA-Z]{36}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
    "generic_secret": re.compile(
        r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
    ),
    "eval_exec_usage": re.compile(r"\b(eval|exec)\s*\("),
    "shell_injection_risk": re.compile(r"subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True"),
    "sql_injection_risk": re.compile(
        r"(?i)(execute|cursor\.execute)\(.*%.*\bor\b.*\%s.*\)"
    ),
}

DEFAULT_EXCLUDES = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 512 * 1024


@dataclass
class Finding:
    path: str
    line: int
    pattern: str
    snippet: str


def scan(root: str, *, max_files: int = 2000) -> dict:
    root_path = Path(root).resolve()
    if not root_path.exists():
        return {"error": f"path not found: {root}"}
    if not root_path.is_dir():
        return {"error": f"path is not a directory: {root}"}

    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0

    for path in _walk(root_path):
        if files_scanned >= max_files:
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                files_skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            files_skipped += 1
            continue
        files_scanned += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            for name, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(
                        Finding(
                            path=str(path.relative_to(root_path)),
                            line=lineno,
                            pattern=name,
                            snippet=line.strip()[:200],
                        )
                    )

    return {
        "root": str(root_path),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "findings_count": len(findings),
        "findings": [f.__dict__ for f in findings[:500]],
        "truncated": len(findings) > 500,
    }


def _walk(root: Path):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.name in DEFAULT_EXCLUDES:
                continue
            if child.is_dir():
                stack.append(child)
            elif child.is_file():
                yield child
