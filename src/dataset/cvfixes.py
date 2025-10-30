"""Normalization logic for the CVEfixes dataset."""

from __future__ import annotations

import gzip
import logging
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .common import normalize_cwe, write_rows

logger = logging.getLogger(__name__)

DATASET_NAME = "cvfixes"
_VALUES_PREFIX = "VALUES("
_VALUES_SUFFIX = ")"


@dataclass(frozen=True)
class _Metadata:
    commit_to_repo: Dict[str, str]
    commit_to_cwes: Dict[str, str]


def _split_sql_values(payload: str) -> List[str]:
    """Split the comma-separated value list of an INSERT statement."""
    values: List[str] = []
    current: List[str] = []
    depth = 0
    in_string = False
    i = 0
    length = len(payload)

    while i < length:
        ch = payload[i]
        if in_string:
            current.append(ch)
            if ch == "'":
                if i + 1 < length and payload[i + 1] == "'":
                    current.append("'")
                    i += 1
                else:
                    in_string = False
            i += 1
            continue

        if ch == "'":
            in_string = True
            current.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            values.append("".join(current).strip())
            current.clear()
            i += 1
            continue
        current.append(ch)
        i += 1

    if current:
        values.append("".join(current).strip())
    return values


def _evaluate_expression(cursor: sqlite3.Cursor, expression: str) -> str:
    expression = expression.strip()
    if not expression:
        return ""
    lowered = expression.lower()
    if lowered in {"null", "'none'", "'nan'"}:
        return ""
    try:
        cursor.execute(f"SELECT {expression}")
    except sqlite3.OperationalError:
        logger.debug("sqlite evaluation failed for %s", expression, exc_info=True)
        return ""
    row = cursor.fetchone()
    value = row[0] if row else ""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    else:
        value = str(value)
    if value.lower() in {"none", "nan"}:
        return ""
    return value


def _normalize_code_text(text: str) -> str:
    if not text:
        return ""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _parse_values_from_insert(line: str) -> Sequence[str]:
    start = line.index(_VALUES_PREFIX) + len(_VALUES_PREFIX)
    end = line.rfind(_VALUES_SUFFIX)
    return _split_sql_values(line[start:end])


def _locate_sql_dump(root: Path) -> Optional[Path]:
    base = root / "cvfixes"
    default = base / "CVEfixes_v1.0.8" / "Data" / "CVEfixes_v1.0.8.sql.gz"
    version_pattern = re.compile(r"CVEfixes_v(\d+(?:\.\d+)*)")
    best_path: Optional[Path] = None
    best_version: Tuple[int, ...] | None = None

    if default.exists():
        best_path = default
        best_version = tuple(int(part) for part in "1.0.8".split("."))

    if base.exists():
        for entry in base.iterdir():
            if not entry.is_dir():
                continue
            match = version_pattern.fullmatch(entry.name)
            if not match:
                continue
            version_tuple = tuple(int(part) for part in match.group(1).split("."))
            candidate = entry / "Data" / f"{entry.name}.sql.gz"
            if not candidate.exists():
                continue
            if best_version is None or version_tuple > best_version:
                best_version = version_tuple
                best_path = candidate

    return best_path


def _collect_metadata(sql_path: Path) -> Tuple[Dict[str, str], Dict[str, Set[str]], Dict[str, Set[str]]]:
    commit_to_repo: Dict[str, str] = {}
    commit_to_cves: Dict[str, Set[str]] = defaultdict(set)
    cve_to_cwes: Dict[str, Set[str]] = defaultdict(set)
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    try:
        with gzip.open(sql_path, "rt", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if line.startswith("INSERT INTO fixes"):
                    values = _parse_values_from_insert(line)
                    if len(values) != 3:
                        continue
                    cve_id = _evaluate_expression(cursor, values[0])
                    commit_hash = _evaluate_expression(cursor, values[1])
                    repo_url = _evaluate_expression(cursor, values[2]).rstrip("/")
                    if not commit_hash:
                        continue
                    if cve_id:
                        commit_to_cves[commit_hash].add(cve_id)
                    if repo_url and commit_hash not in commit_to_repo:
                        commit_to_repo[commit_hash] = repo_url
                elif line.startswith("INSERT INTO cwe_classification"):
                    values = _parse_values_from_insert(line)
                    if len(values) != 2:
                        continue
                    cve_id = _evaluate_expression(cursor, values[0])
                    raw_cwe = _evaluate_expression(cursor, values[1])
                    cwe = normalize_cwe(raw_cwe)
                    if cve_id and cwe:
                        cve_to_cwes[cve_id].add(cwe)
    finally:
        connection.close()
    return commit_to_repo, commit_to_cves, cve_to_cwes


def _build_metadata(commit_to_repo: Dict[str, str], commit_to_cves: Dict[str, Set[str]], cve_to_cwes: Dict[str, Set[str]]) -> _Metadata:
    commit_to_cwes: Dict[str, str] = {}
    for commit_hash, cves in commit_to_cves.items():
        cwe_set: Set[str] = set()
        for cve_id in cves:
            cwe_set.update(cve_to_cwes.get(cve_id, set()))
        commit_to_cwes[commit_hash] = "|".join(sorted(cwe_set))
    return _Metadata(commit_to_repo=commit_to_repo, commit_to_cwes=commit_to_cwes)


def _build_commit_url(repo_url: str, commit_hash: str) -> str:
    if not repo_url or not commit_hash:
        return ""
    return f"{repo_url.rstrip('/')}/commit/{commit_hash}"


def _generate_rows(
    sql_path: Path,
    metadata: _Metadata,
) -> Iterator[List[str]]:
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    skipped_empty = 0
    skipped_identical = 0
    missing_repo = 0
    missing_cwe = 0
    try:
        with gzip.open(sql_path, "rt", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if not line.startswith("INSERT INTO file_change"):
                    if line.startswith("INSERT INTO method_change"):
                        break
                    continue
                values = _parse_values_from_insert(line)
                if len(values) < 16:
                    continue
                commit_hash = _evaluate_expression(cursor, values[1])
                language = _evaluate_expression(cursor, values[15]).strip().lower()
                code_after = _normalize_code_text(_evaluate_expression(cursor, values[10]))
                code_before = _normalize_code_text(_evaluate_expression(cursor, values[11]))
                if not code_before or not code_after:
                    skipped_empty += 1
                    continue
                if code_before.strip() == code_after.strip():
                    skipped_identical += 1
                    continue

                repo_url = metadata.commit_to_repo.get(commit_hash, "")
                cwe = metadata.commit_to_cwes.get(commit_hash, "")
                if not repo_url:
                    missing_repo += 1
                if not cwe:
                    missing_cwe += 1

                yield [
                    cwe,
                    code_before,
                    code_after,
                    _build_commit_url(repo_url, commit_hash),
                    language,
                ]
    finally:
        connection.close()
        if skipped_empty:
            logger.debug("cvfixes skipped %d entries lacking code", skipped_empty)
        if skipped_identical:
            logger.debug("cvfixes skipped %d entries with identical before/after", skipped_identical)
        if missing_repo:
            logger.debug("cvfixes missing repository URL for %d commits", missing_repo)
        if missing_cwe:
            logger.debug("cvfixes missing CWE classifications for %d commits", missing_cwe)


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    sql_path = _locate_sql_dump(root)
    if sql_path is None or not sql_path.exists():
        logger.warning("CVEfixes SQL dump not found under %s", root / "cvfixes")
        return None

    logger.info("Loading CVEfixes metadata from %s", sql_path)
    commit_to_repo, commit_to_cves, cve_to_cwes = _collect_metadata(sql_path)
    metadata = _build_metadata(commit_to_repo, commit_to_cves, cve_to_cwes)
    logger.info(
        "CVEfixes metadata loaded: %d commits, %d CVEs with CWE labels",
        len(metadata.commit_to_repo),
        len(cve_to_cwes),
    )

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path,
        _generate_rows(sql_path, metadata),
        limit=limit,
    )
    if rows_written == 0:
        logger.warning("CVEfixes produced no rows for %s", output_path)
    else:
        extra = " (truncated)" if truncated else ""
        logger.info("CVEfixes: wrote %d rows to %s%s", rows_written, output_path, extra)
    return output_path, rows_written, truncated


__all__ = ["normalize", "DATASET_NAME"]
