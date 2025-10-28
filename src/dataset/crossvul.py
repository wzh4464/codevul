"""Normalization logic for the crossvul dataset."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .common import (
    ensure_https,
    normalize_cwe,
    read_text_with_fallback,
    write_rows,
)

logger = logging.getLogger(__name__)

DATASET_NAME = "crossvul"


def _collect_file_index(dataset_root: Path) -> Dict[str, Path]:
    file_index: Dict[str, Path] = {}
    for path in dataset_root.rglob("*"):
        if path.is_file() and path.name.startswith(("bad_", "good_")):
            file_index[path.name] = path
    return file_index


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    dataset_root = root / "crossvul"
    metadata_path = dataset_root / "metadata.json"
    if not metadata_path.exists():
        logger.warning("Missing crossvul metadata: %s", metadata_path)
        return None

    file_index = _collect_file_index(dataset_root)
    if not file_index:
        logger.warning("No snippet files found under %s", dataset_root)
        return None

    with metadata_path.open("r", encoding="utf-8") as fh:
        records = json.load(fh)

    def generate() -> Iterator[List[str]]:
        for record in records:
            cwe = normalize_cwe(record.get("cwe"))
            commit_url = ensure_https(record.get("url"))
            file_pairs: Dict[str, Dict[str, str]] = {}

            for file_info in record.get("files", []):
                db_name = file_info.get("database_name")
                if not db_name:
                    continue
                source_path = file_index.get(db_name)
                if source_path is None:
                    logger.warning("crossvul missing snippet %s", db_name)
                    continue

                suffix = db_name.split("_", 1)[1] if "_" in db_name else db_name
                pair = file_pairs.setdefault(suffix, {})
                code = read_text_with_fallback(source_path)

                if db_name.startswith("bad"):
                    pair["code_before"] = code
                elif db_name.startswith("good"):
                    pair["code_after"] = code
                pair.setdefault("language", source_path.parent.name)

            for suffix, pair in file_pairs.items():
                code_before = pair.get("code_before")
                code_after = pair.get("code_after")
                if not code_before or not code_after:
                    logger.warning(
                        "crossvul incomplete pair %s (cwe=%s, commit=%s)",
                        suffix,
                        cwe,
                        commit_url,
                    )
                    continue
                yield [
                    cwe,
                    code_before,
                    code_after,
                    commit_url,
                    pair.get("language", ""),
                ]

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path, generate(), limit=limit
    )
    if rows_written == 0:
        logger.warning("crossvul produced no rows for %s", output_path)
    else:
        info_extra = " (truncated)" if truncated else ""
        logger.info(
            "crossvul: wrote %d rows to %s%s",
            rows_written,
            output_path,
            info_extra,
        )
    return output_path, rows_written, truncated
