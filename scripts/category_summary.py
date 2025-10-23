#!/usr/bin/env python3
"""Generate per-category CWE summaries from cwe_counts.json."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]


def _load_collect(root: Path) -> List[Tuple[str, str, List[str]]]:
    """Return a list of (top_name, sub_name, [cwe ids]) from collect.json."""
    collect_path = root / "collect.json"
    with collect_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    categories: List[Tuple[str, str, List[str]]] = []
    for top_name, sub_map in data.items():
        for sub_name, id_list in sub_map.items():
            cwes = [f"CWE-{int(str(cid))}" for cid in id_list]
            categories.append((top_name, sub_name, cwes))
    return categories


def _load_counts(root: Path) -> dict:
    counts_path = root / "cwe_counts.json"
    with counts_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def generate_category_summary() -> None:
    """Aggregate CWE counts by second-level category and emit CSV reports."""
    collect_path = ROOT / "collect.json"
    counts_path = ROOT / "cwe_counts.json"
    if not collect_path.exists() or not counts_path.exists():
        print("Missing collect.json or cwe_counts.json; skip category summary.")
        return

    categories = _load_collect(ROOT)
    counts = _load_counts(ROOT)
    desired_order = [
        "crossvul",
        "megavul",
        "MSR",
        "primevul",
        "cvfixes",
        "juliet",
        "sven",
        "devign",
        "ReVeal",
    ]
    datasets = [name for name in desired_order if name in counts["datasets"]]

    summary_rows: List[List[object]] = []
    zero_rows: List[List[object]] = []

    for top_name, sub_name, cwes in categories:
        per_dataset: List[int] = []
        for dataset in datasets:
            per_cwe: Dict[str, int] = counts["datasets"][dataset]["per_cwe"]
            per_dataset.append(sum(per_cwe.get(cwe, 0) for cwe in cwes))
        total = sum(per_dataset)
        summary_rows.append([top_name, sub_name, total, *per_dataset])
        if total == 0:
            zero_rows.append([top_name, sub_name])

    summary_path = ROOT / "category_summary.csv"
    zero_path = ROOT / "category_summary_zero.csv"

    header = ["一级分类", "二级分类", "total", *datasets]
    with summary_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(summary_rows)

    with zero_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["一级分类", "二级分类"])
        writer.writerows(zero_rows)

    print(
        f"Category summaries written to {summary_path.name} "
        f"({len(summary_rows)} rows, {len(zero_rows)} zero categories)."
    )


if __name__ == "__main__":
    generate_category_summary()
