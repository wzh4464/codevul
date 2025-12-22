"""CVE ID extraction from CVEfixes database."""

from __future__ import annotations

import gzip
import logging
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


def extract_commit_hash_from_url(commit_url: str) -> Optional[str]:
    """
    Extract commit hash from GitHub commit URL.

    Args:
        commit_url: GitHub commit URL (e.g., https://github.com/user/repo/commit/abc123)

    Returns:
        Commit hash or None if not found
    """
    if not commit_url:
        return None

    # Pattern: /commit/[hash]
    match = re.search(r'/commit/([0-9a-f]+)', commit_url)
    if match:
        return match.group(1)

    return None


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
    """Evaluate SQL expression."""
    expression = expression.strip()
    if not expression:
        return ""
    lowered = expression.lower()
    if lowered in {"null", "'none'", "'nan'"}:
        return ""
    try:
        cursor.execute(f"SELECT {expression}")
    except sqlite3.OperationalError:
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


def load_cvefixes_cve_mapping(datasets_dir: Path) -> Dict[str, str]:
    """
    Load commit hash to CVE ID mapping from CVEfixes SQL dump.

    Args:
        datasets_dir: Root datasets directory containing cvefixes/CVEfixes_v*/Data/*.sql.gz

    Returns:
        Dictionary mapping commit hash to primary CVE ID
    """
    # Locate SQL dump
    sql_path = None
    cvefixes_dir = datasets_dir / "cvefixes"

    if cvefixes_dir.exists():
        # Look for CVEfixes_v*.*.*/Data/CVEfixes_v*.*.*.sql.gz
        for version_dir in sorted(cvefixes_dir.iterdir(), reverse=True):
            if version_dir.is_dir() and version_dir.name.startswith("CVEfixes_v"):
                data_dir = version_dir / "Data"
                if data_dir.exists():
                    for sql_file in data_dir.glob("*.sql.gz"):
                        sql_path = sql_file
                        break
                if sql_path:
                    break

    if not sql_path or not sql_path.exists():
        logger.warning("CVEfixes SQL dump not found, CVE extraction will be skipped")
        return {}

    logger.info(f"Loading CVE mapping from {sql_path}...")

    commit_to_cves: Dict[str, Set[str]] = defaultdict(set)
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    try:
        with gzip.open(sql_path, "rt", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if line.startswith("INSERT INTO fixes"):
                    values = _split_sql_values(line[line.index("VALUES(") + 7:line.rfind(")")])
                    if len(values) != 3:
                        continue
                    cve_id = _evaluate_expression(cursor, values[0])
                    commit_hash = _evaluate_expression(cursor, values[1])
                    if commit_hash and cve_id:
                        commit_to_cves[commit_hash].add(cve_id)
    finally:
        connection.close()

    # Convert to single CVE per commit (take the first one)
    commit_to_cve = {
        commit: sorted(cves)[0] if cves else None
        for commit, cves in commit_to_cves.items()
    }

    logger.info(f"Loaded CVE mapping for {len(commit_to_cve)} commits")
    return commit_to_cve
