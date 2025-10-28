"""Shared helpers for dataset normalization."""

from __future__ import annotations

import csv
import json
import logging
import re
import sys
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

SCHEMA: List[str] = ["cwe", "code_before", "code_after", "commit_url", "language"]
CWE_PATTERN = re.compile(r"(?i)cwe[-_\\s]*(\\d+)")
csv.field_size_limit(sys.maxsize)


def normalize_cwe(value: object) -> str:
    """Convert a raw CWE reference into the canonical 'CWE-<num>' form."""
    if value is None:
        return ""
    if isinstance(value, int):
        return f"CWE-{value}"

    text = str(value).strip()
    if not text:
        return ""

    match = CWE_PATTERN.search(text)
    if match:
        return f"CWE-{int(match.group(1))}"

    return text


def ensure_https(url: Optional[str]) -> str:
    """Ensure URLs include a scheme and trim whitespace."""
    if not url:
        return ""
    url = url.strip()
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    return "https://" + url.lstrip("/")


def guess_language_from_filename(name: Optional[str]) -> str:
    """Best-effort language guess based on file extension."""
    if not name or name in {"None", "null"}:
        return ""
    suffix = Path(name).suffix.lower().lstrip(".")
    if not suffix:
        return ""
    mapping = {
        "c": "c",
        "h": "c",
        "cc": "cpp",
        "cpp": "cpp",
        "cxx": "cpp",
        "hpp": "cpp",
        "hxx": "cpp",
        "java": "java",
        "py": "python",
        "cs": "csharp",
        "js": "javascript",
        "ts": "typescript",
        "rb": "ruby",
        "php": "php",
        "jsp": "jsp",
        "go": "go",
        "rs": "rust",
        "swift": "swift",
        "kt": "kotlin",
        "m": "objective-c",
        "mm": "objective-cpp",
        "scala": "scala",
        "vb": "vb",
        "pl": "perl",
        "lua": "lua",
        "sh": "shell",
    }
    return mapping.get(suffix, suffix)


def read_text_with_fallback(path: Path) -> str:
    """Read a text file using UTF-8 with a latin-1 fallback."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def write_rows(
    path: Path,
    rows: Iterable[Sequence[str]],
    *,
    limit: Optional[int] = None,
) -> Tuple[int, bool]:
    """Write rows to a CSV file and return (row_count, truncated?)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    truncated = False
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(SCHEMA)
        for row in rows:
            writer.writerow(row)
            count += 1
            if limit is not None and count >= limit:
                truncated = True
                break
    return count, truncated


def iter_json_array(path: Path, chunk_size: int = 1_048_576) -> Iterator[dict]:
    """Stream JSON objects from a large array without loading the whole file."""
    decoder = json.JSONDecoder()
    buffer = ""
    in_array = False

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buffer += chunk

            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break

                if not in_array:
                    if buffer.startswith("["):
                        in_array = True
                        buffer = buffer[1:]
                        continue
                    raise ValueError(f"{path} must start with a JSON array.")

                if buffer.startswith("]"):
                    return

                try:
                    obj, offset = decoder.raw_decode(buffer)
                except JSONDecodeError:
                    break

                yield obj
                buffer = buffer[offset:].lstrip()
                if buffer.startswith(","):
                    buffer = buffer[1:]

        buffer = buffer.lstrip()
        if in_array and buffer.startswith("]"):
            return
        if buffer:
            raise ValueError(f"Unexpected trailing data in {path}: {buffer[:80]!r}")
