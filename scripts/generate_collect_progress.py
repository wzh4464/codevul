#!/usr/bin/env python3
"""Generate collect_progress.json with sample counts from benchmark_transformed.json."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict


ROOT = Path(__file__).resolve().parents[1]


def load_benchmark_stats() -> Dict[str, Dict]:
    """
    Load benchmark_transformed.json and count entries per CWD.
    Returns dict: {cwd_id: {count, by_language: {lang: count}}}
    """
    benchmark_path = ROOT / "benchmark_transformed.json"
    if not benchmark_path.exists():
        print(f"Warning: {benchmark_path} not found")
        return {}

    with benchmark_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    stats = defaultdict(lambda: {"count": 0, "by_language": defaultdict(int)})

    for language, cwds in data.items():
        for cwd_id, entries in cwds.items():
            count = len(entries)
            stats[cwd_id]["count"] += count
            stats[cwd_id]["by_language"][language] += count

    # Convert defaultdict to regular dict for JSON serialization
    result = {}
    for cwd_id, data in stats.items():
        result[cwd_id] = {
            "count": data["count"],
            "by_language": dict(data["by_language"])
        }

    return result


def add_progress_to_item(item: dict, stats: Dict[str, Dict]) -> dict:
    """
    Add progress information to a CWD item and its children.
    Returns modified item with added fields: sample_count, by_language
    """
    # Create a copy to avoid modifying the original
    result = item.copy()

    cwd_id = result.get("id", "")
    if cwd_id and cwd_id in stats:
        result["sample_count"] = stats[cwd_id]["count"]
        result["by_language"] = stats[cwd_id]["by_language"]
    else:
        result["sample_count"] = 0
        result["by_language"] = {}

    # Recursively process children
    if "children" in result:
        result["children"] = [
            add_progress_to_item(child, stats)
            for child in result["children"]
        ]

    return result


def generate_collect_progress():
    """Generate collect_progress.json with sample counts."""
    print("=" * 80)
    print("GENERATING COLLECT_PROGRESS.JSON")
    print("=" * 80)
    print()

    # Load collect.json
    collect_path = ROOT / "collect.json"
    if not collect_path.exists():
        print(f"Error: {collect_path} not found")
        return

    with collect_path.open("r", encoding="utf-8") as fh:
        collect_data = json.load(fh)

    # Load benchmark statistics
    print("Loading benchmark statistics...")
    stats = load_benchmark_stats()
    print(f"Loaded statistics for {len(stats)} CWDs")
    print()

    # Add progress information to collect.json structure
    print("Adding progress information to collect.json structure...")
    result = {}

    for cat_name, category in collect_data.items():
        if not isinstance(category, dict):
            result[cat_name] = category
            continue

        result[cat_name] = {
            "id": category.get("id", ""),
            "items": []
        }

        items = category.get("items", [])
        for item in items:
            if not isinstance(item, dict):
                result[cat_name]["items"].append(item)
                continue

            # Add progress to this item and its children
            item_with_progress = add_progress_to_item(item, stats)
            result[cat_name]["items"].append(item_with_progress)

    # Calculate summary statistics
    total_cwds = 0
    covered_cwds = 0
    total_samples = 0

    def count_cwds(item):
        nonlocal total_cwds, covered_cwds, total_samples
        if "id" in item and item["id"]:
            total_cwds += 1
            sample_count = item.get("sample_count", 0)
            if sample_count > 0:
                covered_cwds += 1
                total_samples += sample_count

        for child in item.get("children", []):
            count_cwds(child)

    for category in result.values():
        if isinstance(category, dict):
            for item in category.get("items", []):
                count_cwds(item)

    # Save to file
    output_path = ROOT / "collect_progress.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)

    print(f"✅ Generated: {output_path}")
    print()
    print("Summary:")
    print(f"  Total CWDs: {total_cwds}")
    print(f"  Covered CWDs: {covered_cwds} ({covered_cwds/total_cwds*100:.1f}%)")
    print(f"  Total samples: {total_samples}")
    print()
    print("=" * 80)


if __name__ == "__main__":
    generate_collect_progress()
