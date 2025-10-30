"""Normalization logic for the Juliet test suite dataset."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .common import normalize_cwe, write_rows

logger = logging.getLogger(__name__)

DATASET_NAME = "juliet"


def _load_arrow_reader(path: Path):
    try:
        import pyarrow.ipc as pa_ipc
        import pyarrow.lib as pa_lib
    except ImportError as exc:  # pragma: no cover - dependency injection
        raise RuntimeError("pyarrow is required to process Juliet splits") from exc

    source = path.open("rb")
    try:
        try:
            reader = pa_ipc.open_file(source)
            batches = (reader.get_batch(i) for i in range(reader.num_record_batches))
        except pa_lib.ArrowInvalid:
            source.seek(0)
            stream = pa_ipc.open_stream(source)
            batches = iter(stream)
        return batches, source
    except Exception:
        source.close()
        raise


def _ensure_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _normalize_code(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _iter_split(path: Path) -> Iterator[Tuple[str, str, str]]:
    try:
        batches, handle = _load_arrow_reader(path)
    except RuntimeError as exc:
        logger.warning("%s", exc)
        return

    try:
        for batch in batches:
            columns = batch.to_pydict()
            filenames = columns.get("filename", [])
            goods = columns.get("good", [])
            bads = columns.get("bad", [])
            count = len(goods)
            for index in range(count):
                filename = _ensure_text(filenames[index]) if index < len(filenames) else ""
                good_code = _normalize_code(_ensure_text(goods[index]))
                bad_code = _normalize_code(_ensure_text(bads[index]) if index < len(bads) else "")
                yield normalize_cwe(filename), bad_code, good_code
    finally:
        handle.close()


def _iter_rows(base: Path, stats: Dict[str, int]) -> Iterator[List[str]]:
    splits: Sequence[str] = (
        "juliet_test_suite_c_1_3-train.arrow",
        "juliet_test_suite_c_1_3-test.arrow",
    )
    for name in splits:
        path = base / name
        if not path.exists():
            logger.warning("Juliet split missing: %s", path)
            continue
        logger.info("Processing Juliet split %s", path.name)
        for cwe, bad_code, good_code in _iter_split(path):
            if not bad_code or not good_code:
                stats["skipped_empty"] += 1
                continue
            stats["processed"] += 1
            yield [
                cwe,
                bad_code,
                good_code,
                "",
                "c",
            ]


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    base = root / "juliet"
    if not base.exists():
        logger.warning("Juliet dataset directory missing under %s", base)
        return None

    stats: Dict[str, int] = {"processed": 0, "skipped_empty": 0}
    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path,
        _iter_rows(base, stats),
        limit=limit,
    )

    if rows_written == 0:
        logger.warning("Juliet produced no rows for %s", output_path)
    else:
        extra = " (truncated)" if truncated else ""
        logger.info("Juliet: wrote %d rows to %s%s", rows_written, output_path, extra)
    if stats["skipped_empty"]:
        logger.debug("Juliet skipped %d rows missing code", stats["skipped_empty"])
    return output_path, rows_written, truncated


__all__ = ["normalize", "DATASET_NAME"]
