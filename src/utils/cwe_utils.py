"""
Common utilities for CWE (Common Weakness Enumeration) processing.

This module provides functions for normalizing CWE identifiers, extracting
CWE numbers, grouping data by CWE, and performing CWE-related analysis.
Also provides CWE to CWD (Code Weakness Dictionary) mapping functionality.
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union


# Re-export normalize_cwe from common module for convenience
try:
    from src.dataset.common import normalize_cwe
except ImportError:
    # Fallback implementation if common module is not available
    CWE_PATTERN = re.compile(r"(?i)cwe[-_\\s]*(\\d+)")

    def normalize_cwe(value: object) -> str:
        """Convert a raw CWE reference into the canonical 'CWE-<num>' form."""
        if value is None:
            return ""
        if isinstance(value, int):
            return f"CWE-{value}"

        text = str(value).strip()
        if not text:
            return ""

        match = CWE_PATTERN.search(text)
        if match:
            return f"CWE-{int(match.group(1))}"

        return text


def extract_cwe_number(cwe_str: str) -> Optional[int]:
    """
    Extract numeric CWE ID from CWE string.

    Args:
        cwe_str: CWE identifier (e.g., "CWE-79", "cwe_79", "79")

    Returns:
        Numeric CWE ID, or None if not found

    Examples:
        >>> extract_cwe_number("CWE-79")
        79
        >>> extract_cwe_number("cwe_89")
        89
        >>> extract_cwe_number("Unknown")
        None
    """
    if not cwe_str:
        return None

    # Try to match CWE pattern
    match = re.search(r"(?i)cwe[-_\s]*(\d+)", str(cwe_str))
    if match:
        return int(match.group(1))

    # Try to parse as integer directly
    try:
        return int(cwe_str)
    except (ValueError, TypeError):
        return None


def is_valid_cwe(cwe_str: str) -> bool:
    """
    Check if string is a valid CWE identifier.

    Args:
        cwe_str: CWE identifier to validate

    Returns:
        True if valid CWE format, False otherwise
    """
    return extract_cwe_number(cwe_str) is not None


def group_by_cwe(
    items: Iterable[Dict[str, Any]],
    cwe_field: str = 'cwe',
    normalize: bool = True
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group items by CWE identifier.

    Args:
        items: Iterable of dictionaries containing CWE field
        cwe_field: Name of the CWE field in dictionaries (default: 'cwe')
        normalize: If True, normalize CWE identifiers (default: True)

    Returns:
        Dictionary mapping CWE identifiers to lists of items
    """
    groups = defaultdict(list)

    for item in items:
        cwe = item.get(cwe_field, 'Unknown')

        if normalize and cwe != 'Unknown':
            cwe = normalize_cwe(cwe)

        groups[cwe].append(item)

    return dict(groups)


def count_cwes(
    items: Iterable[Dict[str, Any]],
    cwe_field: str = 'cwe',
    normalize: bool = True,
    exclude_unknown: bool = False
) -> Counter:
    """
    Count occurrences of each CWE in items.

    Args:
        items: Iterable of dictionaries containing CWE field
        cwe_field: Name of the CWE field in dictionaries (default: 'cwe')
        normalize: If True, normalize CWE identifiers (default: True)
        exclude_unknown: If True, exclude Unknown/empty CWEs (default: False)

    Returns:
        Counter object with CWE counts
    """
    counter = Counter()

    for item in items:
        cwe = item.get(cwe_field, 'Unknown')

        if normalize and cwe not in ('Unknown', '', None):
            cwe = normalize_cwe(cwe)

        if exclude_unknown and cwe in ('Unknown', '', None):
            continue

        counter[cwe] += 1

    return counter


def get_cwe_statistics(
    items: Iterable[Dict[str, Any]],
    cwe_field: str = 'cwe',
    normalize: bool = True
) -> Dict[str, Any]:
    """
    Get comprehensive CWE statistics from items.

    Args:
        items: Iterable of dictionaries containing CWE field
        cwe_field: Name of the CWE field in dictionaries (default: 'cwe')
        normalize: If True, normalize CWE identifiers (default: True)

    Returns:
        Dictionary with statistics including:
        - total_items: Total number of items
        - unique_cwes: Number of unique CWEs
        - cwe_counts: Counter of CWE occurrences
        - most_common: List of (cwe, count) tuples for most common CWEs
        - unknown_count: Number of items with unknown CWE
    """
    items_list = list(items)  # Materialize if generator
    counter = count_cwes(items_list, cwe_field=cwe_field, normalize=normalize)

    total = len(items_list)
    unknown_count = counter.get('Unknown', 0) + counter.get('', 0)

    return {
        'total_items': total,
        'unique_cwes': len(counter),
        'cwe_counts': counter,
        'most_common': counter.most_common(10),
        'unknown_count': unknown_count,
        'valid_count': total - unknown_count
    }


def format_cwe_statistics(
    stats: Dict[str, Any],
    top_n: int = 10,
    show_percentages: bool = True
) -> str:
    """
    Format CWE statistics as a human-readable string.

    Args:
        stats: Statistics dictionary from get_cwe_statistics
        top_n: Number of top CWEs to show (default: 10)
        show_percentages: If True, show percentages (default: True)

    Returns:
        Formatted statistics string
    """
    lines = []
    lines.append("=" * 70)
    lines.append("CWE Statistics")
    lines.append("=" * 70)

    total = stats['total_items']
    lines.append(f"Total items: {total:,}")
    lines.append(f"Unique CWEs: {stats['unique_cwes']}")
    lines.append(f"Valid CWEs: {stats['valid_count']:,}")
    lines.append(f"Unknown CWEs: {stats['unknown_count']:,}")

    if stats['most_common']:
        lines.append(f"\nTop {top_n} Most Common CWEs:")
        lines.append("-" * 70)

        for cwe, count in stats['most_common'][:top_n]:
            if show_percentages and total > 0:
                percentage = (count / total) * 100
                lines.append(f"  {cwe:20s}: {count:6,} ({percentage:5.2f}%)")
            else:
                lines.append(f"  {cwe:20s}: {count:6,}")

    lines.append("=" * 70)

    return "\n".join(lines)


def split_by_cwe_size(
    items_by_cwe: Dict[str, List[Any]],
    large_threshold: int = 5000,
    medium_threshold: int = 100
) -> Tuple[Dict[str, List[Any]], Dict[str, List[Any]], Dict[str, List[Any]]]:
    """
    Split CWE groups by size into large, medium, and small categories.

    Args:
        items_by_cwe: Dictionary mapping CWE to list of items
        large_threshold: Minimum size for large category (default: 5000)
        medium_threshold: Minimum size for medium category (default: 100)

    Returns:
        Tuple of (large_cwes, medium_cwes, small_cwes) dictionaries
    """
    large = {}
    medium = {}
    small = {}

    for cwe, items in items_by_cwe.items():
        count = len(items)

        if count >= large_threshold:
            large[cwe] = items
        elif count >= medium_threshold:
            medium[cwe] = items
        else:
            small[cwe] = items

    return large, medium, small


def filter_by_cwe(
    items: Iterable[Dict[str, Any]],
    cwe_list: List[str],
    cwe_field: str = 'cwe',
    normalize: bool = True
) -> List[Dict[str, Any]]:
    """
    Filter items by CWE identifiers.

    Args:
        items: Iterable of dictionaries containing CWE field
        cwe_list: List of CWE identifiers to keep
        cwe_field: Name of the CWE field in dictionaries (default: 'cwe')
        normalize: If True, normalize CWE identifiers before comparison (default: True)

    Returns:
        List of items matching the CWE list
    """
    if normalize:
        cwe_set = {normalize_cwe(cwe) for cwe in cwe_list}
    else:
        cwe_set = set(cwe_list)

    result = []
    for item in items:
        cwe = item.get(cwe_field, '')

        if normalize and cwe:
            cwe = normalize_cwe(cwe)

        if cwe in cwe_set:
            result.append(item)

    return result


# ============================================================================
# CWE to CWD (Code Weakness Dictionary) Mapping
# ============================================================================

def load_cwd_mapping(collect_json_path: Union[str, Path]) -> Dict[str, List[str]]:
    """
    Load CWE to CWD mapping from collect.json file.

    The collect.json file contains a nested structure with categories, items,
    and children. Each item has an "id" (CWD like "CWD-1044") and a "cwe" array.
    This function builds a mapping from CWE identifiers to CWD identifiers.

    Args:
        collect_json_path: Path to collect.json file

    Returns:
        Dictionary mapping CWE (e.g., "CWE-73") to list of CWDs (e.g., ["CWD-1044"])

    Example:
        >>> mapping = load_cwd_mapping("collect.json")
        >>> mapping["CWE-73"]
        ["CWD-1044"]
    """
    with open(collect_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    cwe_to_cwd = defaultdict(list)

    def process_item(item: Dict[str, Any]) -> None:
        """Recursively process an item and its children."""
        cwd_id = item.get('id', '')
        cwe_list = item.get('cwe', [])

        # Map each CWE in the list to this CWD
        for cwe in cwe_list:
            # Normalize CWE format
            normalized_cwe = normalize_cwe(cwe)
            if normalized_cwe and normalized_cwe not in ('Unknown', ''):
                cwe_to_cwd[normalized_cwe].append(cwd_id)

        # Process children recursively
        children = item.get('children', [])
        for child in children:
            process_item(child)

    # Process all categories and their items
    for category_name, category_data in data.items():
        items = category_data.get('items', [])
        for item in items:
            process_item(item)

    # Convert defaultdict to regular dict
    return dict(cwe_to_cwd)


def get_cwd_for_cwe(cwe: str, cwe_to_cwd_mapping: Dict[str, List[str]]) -> Optional[str]:
    """
    Get the primary CWD identifier for a given CWE.

    Args:
        cwe: CWE identifier (e.g., "CWE-73")
        cwe_to_cwd_mapping: CWE to CWD mapping from load_cwd_mapping()

    Returns:
        Primary CWD identifier (first one in the list), or None if not found

    Example:
        >>> mapping = load_cwd_mapping("collect.json")
        >>> get_cwd_for_cwe("CWE-73", mapping)
        "CWD-1044"
    """
    normalized_cwe = normalize_cwe(cwe)
    if not normalized_cwe or normalized_cwe in ('Unknown', ''):
        return None

    cwd_list = cwe_to_cwd_mapping.get(normalized_cwe, [])
    return cwd_list[0] if cwd_list else None


def get_all_cwds_for_cwe(cwe: str, cwe_to_cwd_mapping: Dict[str, List[str]]) -> List[str]:
    """
    Get all CWD identifiers for a given CWE.

    Args:
        cwe: CWE identifier (e.g., "CWE-73")
        cwe_to_cwd_mapping: CWE to CWD mapping from load_cwd_mapping()

    Returns:
        List of CWD identifiers, or empty list if not found

    Example:
        >>> mapping = load_cwd_mapping("collect.json")
        >>> get_all_cwds_for_cwe("CWE-73", mapping)
        ["CWD-1044"]
    """
    normalized_cwe = normalize_cwe(cwe)
    if not normalized_cwe or normalized_cwe in ('Unknown', ''):
        return []

    return cwe_to_cwd_mapping.get(normalized_cwe, [])


def is_unknown_cwe(cwe: str) -> bool:
    """
    Check if a CWE identifier is unknown or invalid.

    Args:
        cwe: CWE identifier to check

    Returns:
        True if the CWE is unknown/invalid, False otherwise

    Examples:
        >>> is_unknown_cwe("Unknown")
        True
        >>> is_unknown_cwe("UNKNOWN")
        True
        >>> is_unknown_cwe("")
        True
        >>> is_unknown_cwe("CWE-79")
        False
    """
    if not cwe or cwe is None:
        return True

    cwe_str = str(cwe).strip()

    # Check for empty string
    if not cwe_str:
        return True

    # Check for "Unknown" variants (case-insensitive)
    if cwe_str.lower() == 'unknown':
        return True

    # Check if it's a valid CWE number
    return not is_valid_cwe(cwe_str)
