"""Normalization logic for the CVEfixes dataset."""

from __future__ import annotations

import gzip
import logging
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from .common import normalize_cwe, write_rows

logger = logging.getLogger(__name__)

DATASET_NAME = "cvefixes"

# Programming languages to include
ALLOWED_LANGUAGES = {"c", "c++", "java"}


def _locate_database(root: Path) -> Optional[Path]:
    """Locate the CVEfixes SQLite database file."""
    base = root / "cvefixes"
    version_pattern = re.compile(r"CVEfixes_v(\d+(?:\.\d+)*)")
    best_path: Optional[Path] = None
    best_version: Optional[Tuple[int, ...]] = None

    if not base.exists():
        return None

    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        match = version_pattern.fullmatch(entry.name)
        if not match:
            continue
        version_tuple = tuple(int(part) for part in match.group(1).split("."))
        candidate_db = entry / "Data" / "CVEfixes.db"

        if candidate_db.exists():
            if best_version is None or version_tuple > best_version:
                best_version = version_tuple
                best_path = candidate_db

    return best_path


def _locate_sql_dump(root: Path) -> Optional[Path]:
    """Locate the CVEfixes SQL dump file."""
    base = root / "cvefixes"
    version_pattern = re.compile(r"CVEfixes_v(\d+(?:\.\d+)*)")
    best_path: Optional[Path] = None
    best_version: Optional[Tuple[int, ...]] = None

    if not base.exists():
        return None

    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        match = version_pattern.fullmatch(entry.name)
        if not match:
            continue
        version_tuple = tuple(int(part) for part in match.group(1).split("."))
        candidate_sql = entry / "Data" / f"{entry.name}.sql.gz"

        if candidate_sql.exists():
            if best_version is None or version_tuple > best_version:
                best_version = version_tuple
                best_path = candidate_sql

    return best_path


def _create_database_from_dump(sql_path: Path, db_path: Path) -> bool:
    """Create SQLite database from SQL dump file."""
    try:
        logger.info("Creating database from %s", sql_path)
        logger.info("This may take several minutes...")

        # Create database by piping decompressed SQL to sqlite3
        with gzip.open(sql_path, "rb") as gz_file:
            process = subprocess.Popen(
                ["sqlite3", str(db_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Read and pipe in chunks to avoid memory issues
            chunk_size = 1024 * 1024  # 1MB chunks
            while True:
                chunk = gz_file.read(chunk_size)
                if not chunk:
                    break
                process.stdin.write(chunk)

            process.stdin.close()
            process.wait()

            if process.returncode != 0:
                error = process.stderr.read().decode("utf-8", errors="ignore")
                logger.error("Database creation failed: %s", error)
                return False

        logger.info("Database created successfully at %s", db_path)
        return True

    except Exception as e:
        logger.error("Failed to create database: %s", e, exc_info=True)
        return False


def _ensure_database(root: Path) -> Optional[Path]:
    """Ensure CVEfixes database exists, creating it if necessary."""
    db_path = _locate_database(root)

    if db_path and db_path.exists():
        logger.info("Using existing database: %s", db_path)
        return db_path

    # Database doesn't exist, need to create it
    sql_path = _locate_sql_dump(root)
    if not sql_path or not sql_path.exists():
        logger.warning("CVEfixes SQL dump not found under %s", root / "cvefixes")
        return None

    # Determine where to create the database
    db_path = sql_path.parent / "CVEfixes.db"

    if not _create_database_from_dump(sql_path, db_path):
        return None

    return db_path


def _build_commit_url(repo_url: str, commit_hash: str) -> str:
    """Build commit URL from repository URL and commit hash."""
    if not repo_url or not commit_hash:
        return ""
    return f"{repo_url.rstrip('/')}/commit/{commit_hash}"


def _normalize_code_text(text: str) -> str:
    """Normalize code text by standardizing line endings."""
    if not text:
        return ""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _generate_rows(db_path: Path) -> Iterator[List[str]]:
    """Generate rows from the CVEfixes database."""
    connection = sqlite3.connect(str(db_path))
    cursor = connection.cursor()

    skipped_empty = 0
    skipped_identical = 0
    skipped_language = 0
    missing_cwe = 0

    try:
        # Query to fetch file changes with CWE information
        # Join file_change with fixes and cwe_classification
        query = """
        SELECT
            fc.hash,
            fx.repo_url,
            fc.programming_language,
            fc.code_before,
            fc.code_after,
            GROUP_CONCAT(DISTINCT wc.cwe_id) as cwes
        FROM file_change fc
        LEFT JOIN fixes fx ON fc.hash = fx.hash
        LEFT JOIN cwe_classification wc ON fx.cve_id = wc.cve_id
        WHERE fc.programming_language IS NOT NULL
        GROUP BY fc.hash, fc.filename, fc.code_before, fc.code_after
        """

        cursor.execute(query)

        for row in cursor.fetchall():
            commit_hash, repo_url, language, code_before, code_after, cwes = row

            # Normalize language
            language = (language or "").strip().lower()

            # Filter by allowed languages
            if language not in ALLOWED_LANGUAGES:
                skipped_language += 1
                continue

            # Normalize code
            code_before = _normalize_code_text(code_before or "")
            code_after = _normalize_code_text(code_after or "")

            # Skip if code is empty
            if not code_before or not code_after:
                skipped_empty += 1
                continue

            # Skip if code is identical
            if code_before.strip() == code_after.strip():
                skipped_identical += 1
                continue

            # Normalize CWEs
            cwe_list = []
            if cwes:
                # GROUP_CONCAT uses comma separator by default
                for cwe_raw in cwes.split(","):
                    cwe = normalize_cwe(cwe_raw)
                    if cwe:
                        cwe_list.append(cwe)

            cwe = "|".join(sorted(set(cwe_list))) if cwe_list else ""

            if not cwe:
                missing_cwe += 1

            yield [
                cwe,
                code_before,
                code_after,
                _build_commit_url(repo_url or "", commit_hash or ""),
                language,
            ]

    finally:
        connection.close()

        if skipped_empty:
            logger.debug("cvefixes skipped %d entries lacking code", skipped_empty)
        if skipped_identical:
            logger.debug("cvefixes skipped %d entries with identical before/after", skipped_identical)
        if skipped_language:
            logger.debug("cvefixes skipped %d entries for non-C/C++/Java languages", skipped_language)
        if missing_cwe:
            logger.debug("cvefixes missing CWE classifications for %d entries", missing_cwe)


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    """
    Normalize the CVEfixes dataset.

    Args:
        root: Root directory containing the dataset
        outdir: Output directory for normalized CSV
        limit: Optional limit on number of rows to write

    Returns:
        Tuple of (output_path, rows_written, truncated) or None if failed
    """
    db_path = _ensure_database(root)
    if not db_path:
        return None

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path,
        _generate_rows(db_path),
        limit=limit,
    )

    if rows_written == 0:
        logger.warning("CVEfixes produced no rows for %s", output_path)
    else:
        extra = " (truncated)" if truncated else ""
        logger.info("CVEfixes: wrote %d rows to %s%s", rows_written, output_path, extra)

    return output_path, rows_written, truncated


__all__ = ["normalize", "DATASET_NAME"]
