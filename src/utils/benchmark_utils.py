"""
Common utilities for benchmark data processing.

This module provides functions for loading, filtering, and analyzing
benchmark datasets with diverse sample selection strategies.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from .json_utils import load_json_safe


def calculate_sample_score(sample: Dict[str, Any]) -> Dict[str, float]:
    """
    Calculate feature scores for a sample.

    This is used for ranking and diversity sampling.

    Args:
        sample: Sample dictionary containing code information

    Returns:
        Dictionary with score metrics:
        - total_lines: Total number of code lines
        - vuln_lines: Number of vulnerable lines
        - avg_length: Average line length
        - max_length: Maximum line length
    """
    benign_lines = sample.get('benign_lines', [])
    vuln_lines = sample.get('vuln_lines', [])

    total_lines = len(benign_lines) + len(vuln_lines)
    vuln_count = len(vuln_lines)

    # Calculate line length statistics
    all_lines = benign_lines + vuln_lines
    if all_lines:
        line_lengths = [len(str(line)) for line in all_lines]
        avg_length = sum(line_lengths) / len(line_lengths)
        max_length = max(line_lengths)
    else:
        avg_length = 0
        max_length = 0

    return {
        'total_lines': total_lines,
        'vuln_lines': vuln_count,
        'avg_length': avg_length,
        'max_length': max_length
    }


def select_diverse_samples(
    samples: List[Dict[str, Any]],
    n: int = 10,
    strategy: str = 'stratified'
) -> List[Dict[str, Any]]:
    """
    Select diverse samples using stratified sampling.

    Strategies:
    - 'stratified': Sample based on total line count distribution
    - 'random': Random selection (requires random module)
    - 'top': Select top N by total lines
    - 'balanced': Try to balance by vulnerability lines

    Args:
        samples: List of sample dictionaries
        n: Number of samples to select (default: 10)
        strategy: Selection strategy (default: 'stratified')

    Returns:
        List of selected samples
    """
    if len(samples) <= n:
        return samples

    if strategy == 'stratified':
        # Calculate scores and sort by total lines
        samples_with_scores = []
        for sample in samples:
            score = calculate_sample_score(sample)
            samples_with_scores.append((sample, score['total_lines']))

        # Sort by total lines
        samples_with_scores.sort(key=lambda x: x[1])

        # Stratified sampling - divide into n bins and select from each
        selected = []
        step = len(samples_with_scores) / n

        for i in range(n):
            idx = int(i * step + step / 2)
            if idx >= len(samples_with_scores):
                idx = len(samples_with_scores) - 1
            selected.append(samples_with_scores[idx][0])

        return selected

    elif strategy == 'top':
        # Select top N by total lines
        samples_with_scores = [
            (sample, calculate_sample_score(sample)['total_lines'])
            for sample in samples
        ]
        samples_with_scores.sort(key=lambda x: x[1], reverse=True)
        return [s[0] for s in samples_with_scores[:n]]

    elif strategy == 'balanced':
        # Try to balance by vulnerability lines
        samples_with_vuln = []
        for sample in samples:
            vuln_count = len(sample.get('vuln_lines', []))
            samples_with_vuln.append((sample, vuln_count))

        samples_with_vuln.sort(key=lambda x: x[1])

        selected = []
        step = len(samples_with_vuln) / n

        for i in range(n):
            idx = int(i * step + step / 2)
            if idx >= len(samples_with_vuln):
                idx = len(samples_with_vuln) - 1
            selected.append(samples_with_vuln[idx][0])

        return selected

    elif strategy == 'random':
        import random
        return random.sample(samples, min(n, len(samples)))

    else:
        raise ValueError(f"Unknown strategy: {strategy}")


def load_benchmark_json(
    file_path: Union[str, Path],
    verbose: bool = False
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """
    Load benchmark JSON file.

    Expected format: { "language": { "cwe": [...samples...] } }

    Args:
        file_path: Path to benchmark JSON file
        verbose: If True, print progress messages

    Returns:
        Dictionary with nested structure: language -> cwe -> samples
    """
    if verbose:
        print(f"Loading benchmark: {file_path}")

    data = load_json_safe(file_path)

    if data is None:
        print(f"Error: Failed to load benchmark from {file_path}", file=sys.stderr)
        sys.exit(1)

    if verbose:
        # Count total samples
        total = sum(
            len(samples)
            for lang_data in data.values()
            for samples in lang_data.values()
        )
        print(f"Loaded {len(data)} languages, {total:,} total samples")

    return data


def group_by_language_and_cwe(
    data: Dict[str, Dict[str, List[Dict[str, Any]]]]
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """
    Ensure data is grouped by language and CWE.

    This is mainly for validation and normalization.

    Args:
        data: Benchmark data

    Returns:
        Same data structure, validated and normalized
    """
    result = defaultdict(lambda: defaultdict(list))

    for language, cwe_dict in data.items():
        if not isinstance(cwe_dict, dict):
            continue

        for cwe, samples in cwe_dict.items():
            if not isinstance(samples, list):
                continue

            result[language][cwe].extend(samples)

    return {lang: dict(cwes) for lang, cwes in result.items()}


def filter_benchmark(
    data: Dict[str, Dict[str, List[Dict[str, Any]]]],
    samples_per_cwe: int = 10,
    strategy: str = 'stratified',
    verbose: bool = False
) -> Tuple[Dict[str, Dict[str, List[Dict[str, Any]]]], Dict[str, Any]]:
    """
    Filter benchmark to keep N representative samples per CWE.

    Args:
        data: Benchmark data (language -> cwe -> samples)
        samples_per_cwe: Number of samples to keep per CWE (default: 10)
        strategy: Sample selection strategy (default: 'stratified')
        verbose: If True, print progress messages

    Returns:
        Tuple of (filtered_data, statistics)
    """
    if verbose:
        print(f"\nFiltering benchmark (keeping {samples_per_cwe} samples per CWE)")

    stats = {
        'original': defaultdict(lambda: defaultdict(int)),
        'filtered': defaultdict(lambda: defaultdict(int)),
        'total_original': 0,
        'total_filtered': 0
    }

    filtered_data = {}

    for lang_idx, (language, cwe_dict) in enumerate(data.items(), 1):
        if verbose:
            print(f"\n[{lang_idx}/{len(data)}] Processing: {language}")

        filtered_data[language] = {}

        for cwe_idx, (cwe, samples) in enumerate(cwe_dict.items(), 1):
            original_count = len(samples)
            stats['original'][language][cwe] = original_count
            stats['total_original'] += original_count

            # Select diverse samples
            selected = select_diverse_samples(samples, n=samples_per_cwe, strategy=strategy)
            filtered_data[language][cwe] = selected

            filtered_count = len(selected)
            stats['filtered'][language][cwe] = filtered_count
            stats['total_filtered'] += filtered_count

            if verbose and (cwe_idx % 10 == 0 or cwe_idx == len(cwe_dict)):
                print(f"  Progress: {cwe_idx}/{len(cwe_dict)} CWEs")

    return filtered_data, stats


def print_benchmark_statistics(
    stats: Dict[str, Any],
    detailed: bool = True
) -> None:
    """
    Print benchmark filtering statistics.

    Args:
        stats: Statistics dictionary from filter_benchmark
        detailed: If True, show per-language and per-CWE details (default: True)
    """
    print("\n" + "=" * 70)
    print(" " * 25 + "Benchmark Statistics")
    print("=" * 70)

    # Overall statistics
    print(f"\n【Overall Statistics】")
    print(f"  Original samples: {stats['total_original']:,}")
    print(f"  Filtered samples: {stats['total_filtered']:,}")

    if stats['total_original'] > 0:
        retention = stats['total_filtered'] / stats['total_original'] * 100
        print(f"  Retention rate: {retention:.2f}%")
        print(f"  Reduced by: {stats['total_original'] - stats['total_filtered']:,}")

    if not detailed:
        print("=" * 70)
        return

    # Per-language statistics
    print(f"\n【Per-Language Statistics】")
    print("-" * 70)

    for language in sorted(stats['original'].keys()):
        lang_original = sum(stats['original'][language].values())
        lang_filtered = sum(stats['filtered'][language].values())
        cwe_count = len(stats['original'][language])

        print(f"\n{language}:")
        print(f"  Samples: {lang_original:,} -> {lang_filtered:,}")
        print(f"  CWE types: {cwe_count}")

        if lang_original > 0:
            retention = lang_filtered / lang_original * 100
            print(f"  Retention: {retention:.2f}%")

        # Show per-CWE details
        print(f"  CWE breakdown:")
        for cwe in sorted(stats['original'][language].keys()):
            orig = stats['original'][language][cwe]
            filt = stats['filtered'][language][cwe]
            if orig > 0:
                pct = filt / orig * 100
                print(f"    {cwe:12s}: {orig:6,} -> {filt:3,} ({pct:5.1f}%)")

    print("\n" + "=" * 70)


def save_benchmark(
    data: Dict[str, Dict[str, List[Dict[str, Any]]]],
    file_path: Union[str, Path],
    indent: Optional[int] = 2,
    verbose: bool = False
) -> bool:
    """
    Save benchmark data to JSON file.

    Args:
        data: Benchmark data to save
        file_path: Path to output JSON file
        indent: JSON indentation level (default: 2)
        verbose: If True, print progress messages

    Returns:
        True if successful, False otherwise
    """
    file_path = Path(file_path)

    if verbose:
        print(f"Saving benchmark to: {file_path}")

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)

        if verbose:
            print("Save completed successfully")

        return True
    except Exception as e:
        print(f"Error saving benchmark: {e}", file=sys.stderr)
        return False


def get_benchmark_summary(
    data: Dict[str, Dict[str, List[Dict[str, Any]]]]
) -> Dict[str, Any]:
    """
    Get summary statistics for benchmark data.

    Args:
        data: Benchmark data

    Returns:
        Dictionary with summary statistics
    """
    languages = list(data.keys())
    total_samples = 0
    cwe_counts = defaultdict(int)
    samples_by_language = {}

    for language, cwe_dict in data.items():
        lang_total = 0
        for cwe, samples in cwe_dict.items():
            count = len(samples)
            total_samples += count
            lang_total += count
            cwe_counts[cwe] += count

        samples_by_language[language] = lang_total

    return {
        'total_samples': total_samples,
        'num_languages': len(languages),
        'languages': languages,
        'num_unique_cwes': len(cwe_counts),
        'samples_by_language': samples_by_language,
        'samples_by_cwe': dict(cwe_counts)
    }
