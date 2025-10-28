"""Normalization logic for the JaConTeBe dataset."""

from __future__ import annotations

import logging
import re
from html import unescape
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .common import (
    ensure_https,
    normalize_cwe,
    read_text_with_fallback,
    write_rows,
)

logger = logging.getLogger(__name__)

DATASET_NAME = "jacontebe"

BUGLIST_RELATIVE_PATH = Path("JaConTeBe") / "docs" / "bugList.html"
VERSIONS_RELATIVE_PATH = Path("JaConTeBe") / "versions.alt"

CATEGORY_TO_CWE = {
    "race": "CWE-362",
    "resource deadlock": "CWE-833",
    "wait-notify deadlock": "CWE-833",
    "inconsistent synchronization": "CWE-820",
}

ROW_PATTERN = re.compile(r"<tr[^>]*>(.*?)</tr>", re.IGNORECASE | re.DOTALL)
CELL_PATTERN = re.compile(r"<td[^>]*>(.*?)</td>", re.IGNORECASE | re.DOTALL)


def _read_buglist(path: Path) -> str:
    try:
        return path.read_text(encoding="gb2312")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def _clean_html_fragment(fragment: str) -> str:
    fragment = fragment.replace("<br>", " ").replace("<br/>", " ")
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    fragment = unescape(fragment)
    fragment = re.sub(r"\s+", " ", fragment)
    return fragment.strip()


def _normalize_category(raw: str) -> str:
    normalized = raw.lower()
    normalized = normalized.replace("windows only", "")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def _parse_buglist(path: Path) -> Dict[str, Dict[str, str]]:
    if not path.exists():
        logger.warning("JaConTeBe bug list not found: %s", path)
        return {}

    text = _read_buglist(path)
    metadata: Dict[str, Dict[str, str]] = {}

    for row in ROW_PATTERN.findall(text):
        cells = [_clean_html_fragment(cell) for cell in CELL_PATTERN.findall(row)]
        if len(cells) < 4:
            continue
        sir_name, bug_link, category, *_rest = cells
        if not sir_name or sir_name.lower() == "sir name":
            continue
        normalized_category = _normalize_category(category)
        cwe = CATEGORY_TO_CWE.get(normalized_category)
        if cwe is None:
            if normalized_category:
                logger.warning(
                    "Unknown JaConTeBe category '%s' for subject %s",
                    normalized_category,
                    sir_name,
                )
            cwe = ""
        else:
            cwe = normalize_cwe(cwe)
        metadata[sir_name] = {
            "cwe": cwe,
            "bug_link": ensure_https(bug_link),
            "raw_category": category,
        }

    return metadata


def _iter_source_files(directory: Path) -> Iterable[Path]:
    if not directory.exists():
        return []
    return sorted(path for path in directory.rglob("*.java") if path.is_file())


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    buglist_path = root / BUGLIST_RELATIVE_PATH
    versions_path = root / VERSIONS_RELATIVE_PATH

    metadata = _parse_buglist(buglist_path)
    if not metadata:
        logger.warning("JaConTeBe metadata could not be parsed; skipping dataset.")
        return None

    known_subjects = set(metadata)
    available_subjects: List[str] = []
    if versions_path.exists():
        for entry in versions_path.iterdir():
            if entry.is_dir() and (entry / "orig").exists():
                available_subjects.append(entry.name)
    else:
        logger.warning("JaConTeBe versions directory missing: %s", versions_path)
    missing_in_buglist = sorted(set(available_subjects) - known_subjects)
    if missing_in_buglist:
        logger.warning(
            "JaConTeBe subjects missing from bug list: %s",
            ", ".join(missing_in_buglist),
        )
    missing_directories = sorted(known_subjects - set(available_subjects))
    if missing_directories:
        logger.warning(
            "JaConTeBe entries without source directories: %s",
            ", ".join(missing_directories),
        )

    def generate() -> Iterator[List[str]]:
        for subject in sorted(metadata):
            orig_dir = versions_path / subject / "orig"
            if not orig_dir.exists():
                logger.warning(
                    "JaConTeBe subject %s has no orig directory at %s",
                    subject,
                    orig_dir,
                )
                continue
            info = metadata[subject]
            cwe = info.get("cwe", "")
            bug_link = info.get("bug_link", "")
            java_files = list(_iter_source_files(orig_dir))
            if not java_files:
                logger.warning("No Java sources found for JaConTeBe subject %s", subject)
                continue
            for java_path in java_files:
                code_before = read_text_with_fallback(java_path)
                yield [
                    cwe,
                    code_before,
                    "",
                    bug_link,
                    "java",
                ]

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(output_path, generate(), limit=limit)
    if rows_written == 0:
        logger.warning("JaConTeBe produced no rows for %s", output_path)
    else:
        logger.info(
            "JaConTeBe: wrote %d rows to %s%s",
            rows_written,
            output_path,
            " (truncated)" if truncated else "",
        )
    return output_path, rows_written, truncated
