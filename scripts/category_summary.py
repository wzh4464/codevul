#!/usr/bin/env python3
"""Analyze benchmark_transformed.json coverage of collect.json hierarchy."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple


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


def _collect_all_cwds(item: dict, parent_id: str = None) -> List[Tuple[str, str, str]]:
    """
    Gather all CWD information from an item and its descendants.
    Returns list of (cwd_id, cwd_name, parent_cwd_id).
    """
    cwds = []
    cwd_id = item.get("id", "")
    cwd_name = item.get("name", "")

    if cwd_id:
        cwds.append((cwd_id, cwd_name, parent_id))

    # Recursively collect children
    for child in item.get("children", []) or []:
        if isinstance(child, dict):
            cwds.extend(_collect_all_cwds(child, cwd_id))

    return cwds


def _load_collect_hierarchy(root: Path) -> Dict:
    """
    Load collect.json and extract hierarchy structure.
    Returns dict with:
    - categories: {cat_name: {id, items: [...]}}
    - all_cwds: {cwd_id: {name, category, parent_id, level}}
    """
    collect_path = root / "collect.json"
    with collect_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    hierarchy = {
        "categories": {},
        "all_cwds": {},
        "level2_cwds": set(),  # Top-level CWDs (no parent)
        "level3_cwds": set()   # Child CWDs (have parent)
    }

    for cat_name, category in data.items():
        if not isinstance(category, dict):
            continue

        cat_id = category.get("id", "")
        hierarchy["categories"][cat_name] = {
            "id": cat_id,
            "items": []
        }

        items = category.get("items", [])
        for item in items:
            if not isinstance(item, dict):
                continue

            # Collect all CWDs from this item and its children
            cwds = _collect_all_cwds(item)
            hierarchy["categories"][cat_name]["items"].extend(cwds)

            for cwd_id, cwd_name, parent_id in cwds:
                level = 3 if parent_id else 2
                hierarchy["all_cwds"][cwd_id] = {
                    "name": cwd_name,
                    "category": cat_name,
                    "parent_id": parent_id,
                    "level": level
                }

                if level == 2:
                    hierarchy["level2_cwds"].add(cwd_id)
                else:
                    hierarchy["level3_cwds"].add(cwd_id)

    return hierarchy


def _load_benchmark_stats(root: Path) -> Dict[str, Dict]:
    """
    Load benchmark_transformed.json and count entries per CWD.
    Returns dict: {cwd_id: {count, by_language: {lang: count}}}
    """
    benchmark_path = root / "benchmark_transformed.json"
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

    return dict(stats)


def generate_category_summary() -> None:
    """Analyze benchmark_transformed.json coverage of collect.json hierarchy."""
    print("=" * 80)
    print("BENCHMARK COVERAGE ANALYSIS")
    print("=" * 80)
    print()

    # Load data
    hierarchy = _load_collect_hierarchy(ROOT)
    benchmark_stats = _load_benchmark_stats(ROOT)

    if not benchmark_stats:
        print("Error: No benchmark data found")
        return

    # Calculate coverage statistics
    total_cwds = len(hierarchy["all_cwds"])
    level2_total = len(hierarchy["level2_cwds"])
    level3_total = len(hierarchy["level3_cwds"])

    covered_cwds = set(benchmark_stats.keys())
    covered_level2 = covered_cwds & hierarchy["level2_cwds"]
    covered_level3 = covered_cwds & hierarchy["level3_cwds"]

    # Overall statistics
    print("📊 OVERALL COVERAGE")
    print("-" * 80)
    print(f"Total CWDs in collect.json: {total_cwds}")
    print(f"  - Level 2 (二级分类): {level2_total}")
    print(f"  - Level 3 (三级分类): {level3_total}")
    print()
    print(f"Covered CWDs in benchmark: {len(covered_cwds)}")
    print(f"  - Level 2: {len(covered_level2)} / {level2_total} ({len(covered_level2)/level2_total*100:.1f}%)")
    print(f"  - Level 3: {len(covered_level3)} / {level3_total} ({len(covered_level3)/level3_total*100:.1f}%)")
    print(f"  - Overall: {len(covered_cwds)} / {total_cwds} ({len(covered_cwds)/total_cwds*100:.1f}%)")
    print()

    # Category breakdown
    print("📋 COVERAGE BY CATEGORY (一级分类)")
    print("-" * 80)

    for cat_name, cat_info in hierarchy["categories"].items():
        cat_cwds = set(cwd_id for cwd_id, _, _ in cat_info["items"])
        cat_covered = cat_cwds & covered_cwds
        cat_level2 = cat_cwds & hierarchy["level2_cwds"]
        cat_level3 = cat_cwds & hierarchy["level3_cwds"]
        cat_covered_level2 = cat_covered & hierarchy["level2_cwds"]
        cat_covered_level3 = cat_covered & hierarchy["level3_cwds"]

        total_entries = sum(benchmark_stats.get(cwd, {}).get("count", 0) for cwd in cat_covered)

        print(f"\n{cat_name} ({cat_info['id']})")
        print(f"  Total CWDs: {len(cat_cwds)} (Level 2: {len(cat_level2)}, Level 3: {len(cat_level3)})")
        print(f"  Covered: {len(cat_covered)} / {len(cat_cwds)} ({len(cat_covered)/len(cat_cwds)*100:.1f}%)")
        print(f"    - Level 2: {len(cat_covered_level2)} / {len(cat_level2)} ({len(cat_covered_level2)/len(cat_level2)*100:.1f}%)" if cat_level2 else "    - Level 2: N/A")
        print(f"    - Level 3: {len(cat_covered_level3)} / {len(cat_level3)} ({len(cat_covered_level3)/len(cat_level3)*100:.1f}%)" if cat_level3 else "    - Level 3: N/A")
        print(f"  Total examples: {total_entries}")

    # Detailed CWD breakdown
    print()
    print("=" * 80)
    print("📝 DETAILED CWD BREAKDOWN")
    print("=" * 80)

    for cat_name, cat_info in hierarchy["categories"].items():
        print(f"\n{'=' * 80}")
        print(f"{cat_name} ({cat_info['id']})")
        print(f"{'=' * 80}")

        # Group by level
        level2_cwds_in_cat = []
        level3_cwds_in_cat = defaultdict(list)

        for cwd_id, cwd_name, parent_id in cat_info["items"]:
            info = hierarchy["all_cwds"][cwd_id]
            count = benchmark_stats.get(cwd_id, {}).get("count", 0)
            by_lang = benchmark_stats.get(cwd_id, {}).get("by_language", {})

            if info["level"] == 2:
                level2_cwds_in_cat.append((cwd_id, cwd_name, count, by_lang))
            else:
                level3_cwds_in_cat[parent_id].append((cwd_id, cwd_name, count, by_lang))

        # Print level 2 CWDs
        for cwd_id, cwd_name, count, by_lang in level2_cwds_in_cat:
            status = "✅" if count > 0 else "❌"
            lang_info = ", ".join(f"{lang}: {c}" for lang, c in by_lang.items()) if by_lang else "N/A"
            print(f"\n  {status} {cwd_id} - {cwd_name}")
            print(f"     Examples: {count} ({lang_info})")

            # Print children if any
            if cwd_id in level3_cwds_in_cat:
                for child_id, child_name, child_count, child_lang in level3_cwds_in_cat[cwd_id]:
                    child_status = "✅" if child_count > 0 else "❌"
                    child_lang_info = ", ".join(f"{lang}: {c}" for lang, c in child_lang.items()) if child_lang else "N/A"
                    print(f"    {child_status} {child_id} - {child_name}")
                    print(f"       Examples: {child_count} ({child_lang_info})")

    print()
    print("=" * 80)
    print("✅ Analysis complete!")
    print("=" * 80)


if __name__ == "__main__":
    generate_category_summary()
