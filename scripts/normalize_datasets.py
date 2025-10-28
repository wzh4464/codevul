#!/usr/bin/env python3
"""Generate normalized per-dataset CSV exports.

Each dataset has its own normalization module under ``src/dataset``. This
command-line wrapper orchestrates those modules and writes the canonical CSVs
into the ``standardized/`` directory (or a user-provided destination).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.dataset import NORMALIZERS  # noqa: E402


def parse_args() -> argparse.Namespace:
    dataset_choices: List[str] = sorted(NORMALIZERS)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        choices=["all", *dataset_choices],
        default="all",
        help="Dataset to normalize (default: all)",
    )
    parser.add_argument(
        "--output-dir",
        default="standardized",
        help="Directory for generated CSV files (default: standardized)",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after writing N rows per dataset (default: no limit)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    root = Path(args.root).resolve()
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = (root / output_dir).resolve()

    dataset_names = (
        sorted(NORMALIZERS)
        if args.dataset == "all"
        else [args.dataset]
    )

    for name in dataset_names:
        normalizer = NORMALIZERS[name]
        logging.info("Normalizing dataset %s", name)
        result = normalizer(root, output_dir, limit=args.limit)
        if result is None:
            logging.warning("Dataset %s skipped due to missing inputs", name)
            continue
        output_path, rows_written, truncated = result
        if truncated:
            logging.info(
                "%s: wrote %d rows to %s (truncated at limit %d)",
                name,
                rows_written,
                output_path,
                args.limit,
            )
        else:
            logging.info(
                "%s: wrote %d rows to %s",
                name,
                rows_written,
                output_path,
            )


if __name__ == "__main__":
    main()
