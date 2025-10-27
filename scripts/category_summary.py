#!/usr/bin/env python3
"""Generate per-category CWE summaries from cwe_counts.json."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]


def _normalize_cwe(value: object) -> str | None:
    """Convert a raw CWE value into the canonical 'CWE-<num>' form."""
    if value is None:
        return None

    if isinstance(value, int):
        return f"CWE-{value}"

    text = str(value).strip()
    if not text:
        return None

    upper = text.upper()
    if upper.startswith("CWE-"):
        try:
            return f"CWE-{int(upper[4:])}"
        except ValueError:
            return None

    if text.isdigit():
        return f"CWE-{int(text)}"

    return None


def _collect_item_cwes(item: dict) -> List[str]:
    """Gather unique CWE identifiers from an item and its descendants."""
    cwes: List[str] = []

    def visit(node: dict) -> None:
        values = node.get("cwe", [])
        if not isinstance(values, (list, tuple)):
            values = [values]
        for raw in values or []:
            normalized = _normalize_cwe(raw)
            if normalized and normalized not in cwes:
                cwes.append(normalized)
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                visit(child)

    visit(item)
    return cwes


def _load_collect(
    root: Path,
) -> Tuple[
    List[Tuple[str, str, List[str]]],
    List[Tuple[str, str, str, List[str]]],
]:
    """Return level-2 and level-3 category mappings from collect.json."""
    collect_path = root / "collect.json"
    with collect_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    level2: List[Tuple[str, str, List[str]]] = []
    level3: List[Tuple[str, str, str, List[str]]] = []
    for top_name, category in data.items():
        items = category.get("items", []) if isinstance(category, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            sub_name = item.get("name")
            if not sub_name:
                continue
            cwes = _collect_item_cwes(item)
            level2.append((top_name, sub_name, cwes))

            for child in item.get("children", []) or []:
                if not isinstance(child, dict):
                    continue
                child_name = child.get("name")
                if not child_name:
                    continue
                child_cwes = _collect_item_cwes(child)
                level3.append((top_name, sub_name, child_name, child_cwes))

    return level2, level3


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

    level2_entries, level3_entries = _load_collect(ROOT)
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

    def build_rows(entries: Iterable[Iterable[object]]) -> Tuple[
        List[List[object]], List[List[object]]
    ]:
        summary_rows: List[List[object]] = []
        zero_rows: List[List[object]] = []
        for entry in entries:
            *labels, cwes = entry
            per_dataset: List[int] = []
            for dataset in datasets:
                per_cwe: Dict[str, int] = counts["datasets"][dataset]["per_cwe"]
                per_dataset.append(sum(per_cwe.get(cwe, 0) for cwe in cwes))
            total = sum(per_dataset)
            summary_rows.append([*labels, total, *per_dataset])
            if total == 0:
                zero_rows.append(list(labels))
        return summary_rows, zero_rows

    level2_rows, level2_zero = build_rows(level2_entries)
    level3_rows, level3_zero = build_rows(level3_entries)

    level2_summary_path = ROOT / "category_summary_level2.csv"
    level2_zero_path = ROOT / "category_summary_level2_zero.csv"
    level3_summary_path = ROOT / "category_summary_level3.csv"
    level3_zero_path = ROOT / "category_summary_level3_zero.csv"

    level2_header = ["一级分类", "二级分类", "total", *datasets]
    with level2_summary_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(level2_header)
        writer.writerows(level2_rows)

    with level2_zero_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["一级分类", "二级分类"])
        writer.writerows(level2_zero)

    level3_header = ["一级分类", "二级分类", "三级分类", "total", *datasets]
    with level3_summary_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(level3_header)
        writer.writerows(level3_rows)

    with level3_zero_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["一级分类", "二级分类", "三级分类"])
        writer.writerows(level3_zero)

    print(
        f"Level-2 summary written to {level2_summary_path.name} "
        f"({len(level2_rows)} rows, {len(level2_zero)} zero categories)."
    )
    print(
        f"Level-3 summary written to {level3_summary_path.name} "
        f"({len(level3_rows)} rows, {len(level3_zero)} zero categories)."
    )


if __name__ == "__main__":
    generate_category_summary()
