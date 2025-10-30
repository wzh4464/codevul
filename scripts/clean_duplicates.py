#!/usr/bin/env python3
"""Remove cross-dataset duplicate rows based on signature manifests."""

from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SignatureEntry:
    """Container for a signature manifest row."""

    signature: str
    dataset: str
    row: int
    cwe: str
    raw: Mapping[str, str]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--standardized-dir",
        default="standardized",
        metavar="DIR",
        help="Directory that stores normalized dataset CSVs.",
    )
    parser.add_argument(
        "--signature-dir",
        default="sig",
        metavar="DIR",
        help="Directory containing per-row signature manifests.",
    )
    parser.add_argument(
        "--output-dir",
        default="clean",
        metavar="DIR",
        help="Destination directory for cleaned datasets.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser.parse_args()


def _load_signature_entries(
    signature_dir: Path,
) -> Tuple[
    Dict[str, List[SignatureEntry]],
    Dict[str, Dict[int, SignatureEntry]],
]:
    """Read signature CSVs and build helper indices."""

    signature_groups: Dict[str, List[SignatureEntry]] = defaultdict(list)
    rows_by_dataset: Dict[str, Dict[int, SignatureEntry]] = defaultdict(dict)

    for path in sorted(signature_dir.glob("*.csv")):
        dataset = path.stem
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    row_index = int(row["row"])
                except (KeyError, ValueError) as exc:
                    raise ValueError(
                        f"Invalid row index in {path}: {row!r}"
                    ) from exc
                signature_value = row.get("signature", "").strip()
                entry = SignatureEntry(
                    signature=signature_value,
                    dataset=dataset,
                    row=row_index,
                    cwe=row.get("cwe", "").strip(),
                    raw=dict(row),
                )
                signature_groups[entry.signature].append(entry)
                rows_by_dataset[dataset][row_index] = entry

    return signature_groups, rows_by_dataset


_CWE_NUMBER_RE = re.compile(r"(\\d+)")


def _cwe_token_count(value: str) -> int:
    if not value:
        return 0
    tokens = [token for token in re.split(r"[;,]", value) if token.strip()]
    return len(tokens) or (1 if value.strip() else 0)


def _cwe_numeric_value(value: str) -> int:
    match = _CWE_NUMBER_RE.search(value)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return sys.maxsize
    return sys.maxsize


def _build_dataset_priority(datasets: Iterable[str]) -> Dict[str, int]:
    return {name: index for index, name in enumerate(sorted(datasets))}


def _select_representative(
    entries: Sequence[SignatureEntry],
    dataset_priority: Mapping[str, int],
) -> SignatureEntry:
    def _key(entry: SignatureEntry) -> Tuple[int, int, int, int]:
        return (
            _cwe_token_count(entry.cwe),
            _cwe_numeric_value(entry.cwe),
            dataset_priority.get(entry.dataset, sys.maxsize),
            entry.row,
        )

    return min(entries, key=_key)


def _prepare_drop_sets(
    signature_groups: Mapping[str, Sequence[SignatureEntry]],
    dataset_priority: Mapping[str, int],
) -> Tuple[Dict[str, Set[int]], Dict[str, int]]:
    drop_rows: Dict[str, Set[int]] = defaultdict(set)
    removed: Dict[str, int] = defaultdict(int)

    for signature, entries in signature_groups.items():
        if not entries:
            continue
        datasets = {entry.dataset for entry in entries}
        if len(datasets) <= 1:
            continue
        representative = _select_representative(entries, dataset_priority)
        for entry in entries:
            if entry == representative:
                continue
            drop_rows[entry.dataset].add(entry.row)
            removed[entry.dataset] += 1

    return drop_rows, removed


def _write_clean_standardized(
    dataset: str,
    source_path: Path,
    destination_path: Path,
    rows_to_drop: Optional[Set[int]],
    signature_rows: Optional[Mapping[int, SignatureEntry]],
    signature_destination: Optional[Path],
) -> Tuple[int, int]:
    """Filter a standardized CSV and emit cleaned data (and signatures)."""

    destination_path.parent.mkdir(parents=True, exist_ok=True)

    sig_writer: Optional[csv.DictWriter]
    if signature_destination is not None:
        signature_destination.parent.mkdir(parents=True, exist_ok=True)
        sig_file = signature_destination.open(
            "w", encoding="utf-8", newline=""
        )
        sig_writer = csv.DictWriter(
            sig_file,
            fieldnames=[
                "signature",
                "dataset",
                "row",
                "cwe",
                "language",
                "code_before_hash",
                "code_after_hash",
                "commit_url",
            ],
        )
        sig_writer.writeheader()
    else:
        sig_file = None
        sig_writer = None

    try:
        with source_path.open("r", encoding="utf-8", newline="") as src_fh, destination_path.open(
            "w", encoding="utf-8", newline=""
        ) as dst_fh:
            reader = csv.DictReader(src_fh)
            fieldnames = reader.fieldnames
            if not fieldnames:
                raise ValueError(f"Missing header in {source_path}")
            writer = csv.DictWriter(dst_fh, fieldnames=fieldnames)
            writer.writeheader()

            kept = 0
            total = 0
            for total, row in enumerate(reader, start=1):
                if rows_to_drop is not None and total in rows_to_drop:
                    continue
                kept += 1
                writer.writerow(row)

                if sig_writer is not None:
                    if signature_rows is None:
                        raise ValueError(
                            f"Signature rows missing for dataset {dataset}"
                        )
                    signature_entry = signature_rows.get(total)
                    if signature_entry is None:
                        raise ValueError(
                            f"Signature entry missing for {dataset} row {total}"
                        )
                    payload = dict(signature_entry.raw)
                    payload["row"] = str(kept)
                    sig_writer.writerow(payload)
    finally:
        if sig_file is not None:
            sig_file.close()

    return total, kept


def _copy_file(source: Path, destination: Path) -> Tuple[int, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with source.open("r", encoding="utf-8", newline="") as src_fh, destination.open(
        "w", encoding="utf-8", newline=""
    ) as dst_fh:
        reader = csv.reader(src_fh)
        writer = csv.writer(dst_fh)
        header = next(reader, None)
        if header is not None:
            writer.writerow(header)
        for row in reader:
            writer.writerow(row)
            total += 1
    return total, total


def main() -> None:
    args = _parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    csv.field_size_limit(sys.maxsize)

    standardized_dir = Path(args.standardized_dir).resolve()
    signature_dir = Path(args.signature_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not standardized_dir.exists():
        raise FileNotFoundError(f"Standardized directory not found: {standardized_dir}")
    if not signature_dir.exists():
        raise FileNotFoundError(f"Signature directory not found: {signature_dir}")

    signature_groups, rows_by_dataset = _load_signature_entries(signature_dir)
    dataset_priority = _build_dataset_priority(rows_by_dataset)
    drop_rows, removed_rows = _prepare_drop_sets(signature_groups, dataset_priority)

    cleaned_standardized_dir = output_dir / "standardized"
    signature_dir_name = signature_dir.name
    cleaned_signatures_dir = output_dir / signature_dir_name

    stats: Dict[str, Tuple[int, int]] = {}

    for csv_path in sorted(standardized_dir.glob("*.csv")):
        dataset = csv_path.stem
        destination = cleaned_standardized_dir / csv_path.name
        if dataset in rows_by_dataset:
            signature_destination = cleaned_signatures_dir / csv_path.name
            total, kept = _write_clean_standardized(
                dataset,
                csv_path,
                destination,
                drop_rows.get(dataset),
                rows_by_dataset.get(dataset),
                signature_destination,
            )
        else:
            total, kept = _copy_file(csv_path, destination)
        stats[dataset] = (total, kept)

    for dataset in sorted(stats):
        total, kept = stats[dataset]
        dropped = total - kept
        removed = removed_rows.get(dataset, 0)
        logger.info(
            "Dataset %s: kept %d/%d rows (dropped %d, duplicates removed %d)",
            dataset,
            kept,
            total,
            dropped,
            removed,
        )


if __name__ == "__main__":
    main()
