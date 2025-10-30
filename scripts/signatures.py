#!/usr/bin/env python3
"""Generate deduplication signatures for standardized dataset rows."""

from __future__ import annotations

import argparse
import csv
import logging
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from src.dataset import NORMALIZERS
from src.signature import compute_row_signature

ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)


def _normalize_dataset_token(value: str) -> str:
    return value.strip().lower().rstrip("/")


def _resolve_datasets(selected: Optional[Iterable[str]]) -> List[str]:
    available = sorted(NORMALIZERS)
    alias_map = {name.lower(): name for name in NORMALIZERS}
    if not selected:
        return available

    tokens: List[str] = []
    for raw in selected:
        token = _normalize_dataset_token(raw or "")
        if not token:
            continue
        if token == "all":
            return available
        mapped = alias_map.get(token)
        if mapped is None:
            raise ValueError(
                f"Unknown dataset '{raw}'. Available datasets: {', '.join(available)}"
            )
        tokens.append(mapped)

    ordered: List[str] = []
    seen = set()
    for name in available:
        if name in tokens and name not in seen:
            ordered.append(name)
            seen.add(name)
    for name in tokens:
        if name not in seen:
            ordered.append(name)
            seen.add(name)

    return ordered


def _iter_rows(path: Path) -> Iterator[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield row


def _write_signatures(
    output_path: Path,
    dataset: str,
    rows: Iterator[Dict[str, str]],
) -> Tuple[int, int]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    distinct = 0
    seen: Dict[str, int] = {}
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        fieldnames = [
            "signature",
            "dataset",
            "row",
            "cwe",
            "language",
            "code_before_hash",
            "code_after_hash",
            "commit_url",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for index, row in enumerate(rows, start=1):
            sig = compute_row_signature(row)
            payload = {
                "signature": sig["signature"],
                "dataset": dataset,
                "row": index,
                "cwe": sig["cwe"],
                "language": sig["language"],
                "code_before_hash": sig["code_before_hash"],
                "code_after_hash": sig["code_after_hash"],
                "commit_url": row.get("commit_url", ""),
            }
            writer.writerow(payload)
            total += 1
            if sig["signature"] not in seen:
                seen[sig["signature"]] = 0
                distinct += 1
            seen[sig["signature"]] += 1
    return total, distinct


def generate_signatures(
    *,
    datasets: Optional[Iterable[str]] = None,
    root: Path = ROOT,
    output_dir: Path = Path("signatures"),
    force: bool = False,
) -> Dict[str, Tuple[int, int]]:
    dataset_names = _resolve_datasets(datasets)
    if not output_dir.is_absolute():
        output_dir = (root / output_dir).resolve()

    stats: Dict[str, Tuple[int, int]] = {}
    for name in dataset_names:
        source_csv = (root / "standardized" / f"{name}.csv").resolve()
        if not source_csv.exists():
            logger.warning("Standardized CSV not found for %s: %s", name, source_csv)
            continue
        output_path = output_dir / f"{name}.csv"
        if output_path.exists() and not force:
            logger.info(
                "Skipping signature generation for %s (found %s).",
                name,
                output_path,
            )
            continue
        logger.info("Generating signatures for %s", name)
        total, distinct = _write_signatures(output_path, name, _iter_rows(source_csv))
        logger.info(
            "%s: wrote %d signatures (%d distinct) to %s",
            name,
            total,
            distinct,
            output_path,
        )
        stats[name] = (total, distinct)
    return stats


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        action="append",
        dest="datasets",
        help="Dataset to process (repeat for multiple). Use 'all' for every dataset.",
        metavar="NAME",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root.",
        metavar="PATH",
    )
    parser.add_argument(
        "--output-dir",
        default="signatures",
        help="Directory for generated signature CSVs.",
        metavar="DIR",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild signatures even if the output file already exists.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    try:
        generate_signatures(
            datasets=args.datasets,
            root=Path(args.root).resolve(),
            output_dir=Path(args.output_dir),
            force=args.force,
        )
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
