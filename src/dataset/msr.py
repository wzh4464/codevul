"""Normalization logic for the MSR dataset."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from .common import ensure_https, normalize_cwe, write_rows

logger = logging.getLogger(__name__)

DATASET_NAME = "msr"


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    csv_path = root / "MSR" / "MSR_data_cleaned.csv"
    if not csv_path.exists():
        logger.warning("Missing MSR dataset: %s", csv_path)
        return None

    def generate() -> Iterator[List[str]]:
        with csv_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                code_before = row.get("func_before")
                code_after = row.get("func_after")
                if not code_before or not code_after:
                    continue
                cwe = normalize_cwe(row.get("CWE ID"))
                commit_url = ensure_https(row.get("codeLink"))
                language = (row.get("lang") or "").strip()
                yield [cwe, code_before, code_after, commit_url, language]

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path, generate(), limit=limit
    )
    if rows_written == 0:
        logger.warning("MSR produced no rows for %s", output_path)
    else:
        info_extra = " (truncated)" if truncated else ""
        logger.info(
            "MSR: wrote %d rows to %s%s", rows_written, output_path, info_extra
        )
    return output_path, rows_written, truncated
