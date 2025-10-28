"""Normalization logic for the primevul dataset."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from itertools import zip_longest
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .common import (
    ensure_https,
    guess_language_from_filename,
    normalize_cwe,
    write_rows,
)

logger = logging.getLogger(__name__)

DATASET_NAME = "primevul"


def _signature(func_text: str) -> str:
    for line in func_text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _bucket_key(record: dict) -> Tuple[str, str]:
    return (
        record.get("project") or "",
        record.get("commit_id") or "",
    )


def _sort_key(record: dict) -> Tuple[str, str, int]:
    file_name = record.get("file_name") or ""
    signature = _signature(record.get("func", ""))
    idx = record.get("idx")
    try:
        idx_val = int(idx)
    except (TypeError, ValueError):
        idx_val = 0
    return (file_name, signature, idx_val)


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    base = root / "primevul"
    jsonl_paths = [
        base / "primevul_train_paired.jsonl",
        base / "primevul_valid_paired.jsonl",
        base / "primevul_test_paired.jsonl",
    ]
    existing_paths = [path for path in jsonl_paths if path.exists()]
    if not existing_paths:
        logger.warning("No primevul JSONL files found under %s", base)
        return None

    aggregated: Dict[Tuple[str, str], Dict[str, List[dict]]] = defaultdict(
        lambda: {"before": [], "after": []}
    )
    for path in existing_paths:
        logger.info("Reading primevul file %s", path)
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                record = json.loads(line)
                key = _bucket_key(record)
                bucket = "before" if record.get("target") == 1 else "after"
                aggregated[key][bucket].append(record)

    def generate() -> Iterator[List[str]]:
        for key, buckets in aggregated.items():
            before_records = sorted(buckets["before"], key=_sort_key)
            after_records = sorted(buckets["after"], key=_sort_key)
            if not before_records or not after_records:
                logger.warning(
                    "primevul unmatched pair for commit %s (before=%d, after=%d)",
                    key,
                    len(before_records),
                    len(after_records),
                )
                continue
            for vuln_record, fix_record in zip_longest(before_records, after_records):
                if not vuln_record or not fix_record:
                    logger.warning(
                        "primevul uneven entries for commit %s (before=%d, after=%d)",
                        key,
                        len(before_records),
                        len(after_records),
                    )
                    continue
                cwes = vuln_record.get("cwe") or []
                normalized_cwes = [
                    normalize_cwe(cwe_value) for cwe_value in cwes if cwe_value
                ]
                cwe = "|".join(filter(None, normalized_cwes))
                language = guess_language_from_filename(
                    vuln_record.get("file_name") or fix_record.get("file_name")
                )
                commit_url = ensure_https(
                    vuln_record.get("commit_url") or fix_record.get("commit_url")
                )
                code_before = vuln_record.get("func", "")
                code_after = fix_record.get("func", "")
                if code_before.strip() == code_after.strip():
                    logger.warning(
                        "primevul identical before/after for commit %s, file %s",
                        key,
                        vuln_record.get("file_name") or fix_record.get("file_name"),
                    )
                    continue
                yield [
                    cwe,
                    code_before,
                    code_after,
                    commit_url,
                    language,
                ]

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path, generate(), limit=limit
    )
    if rows_written == 0:
        logger.warning("primevul produced no rows for %s", output_path)
    else:
        info_extra = " (truncated)" if truncated else ""
        logger.info(
            "primevul: wrote %d rows to %s%s",
            rows_written,
            output_path,
            info_extra,
        )
    return output_path, rows_written, truncated
