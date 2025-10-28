"""Normalization logic for the SVEN dataset."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from .common import (
    ensure_https,
    guess_language_from_filename,
    normalize_cwe,
    write_rows,
)

logger = logging.getLogger(__name__)

DATASET_NAME = "sven"


def _iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    base = root / "sven" / "data_train_val"
    if not base.exists():
        logger.warning("Missing sven dataset: %s", base)
        return None

    jsonl_paths: List[Path] = []
    for split in ("train", "val"):
        split_dir = base / split
        if split_dir.exists():
            jsonl_paths.extend(sorted(split_dir.glob("cwe-*.jsonl")))

    if not jsonl_paths:
        logger.warning("No sven jsonl files found under %s", base)
        return None

    def generate() -> Iterator[List[str]]:
        for path in jsonl_paths:
            for record in _iter_jsonl(path):
                code_before = record.get("func_src_before")
                code_after = record.get("func_src_after")
                if not code_before or not code_after:
                    continue
                cwe = normalize_cwe(record.get("vul_type"))
                commit_url = ensure_https(record.get("commit_link"))
                language = guess_language_from_filename(record.get("file_name"))
                yield [cwe, code_before, code_after, commit_url, language]

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path, generate(), limit=limit
    )
    if rows_written == 0:
        logger.warning("sven produced no rows for %s", output_path)
    else:
        info_extra = " (truncated)" if truncated else ""
        logger.info(
            "sven: wrote %d rows to %s%s",
            rows_written,
            output_path,
            info_extra,
        )
    return output_path, rows_written, truncated
