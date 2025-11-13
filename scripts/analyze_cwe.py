#!/usr/bin/env python3
"""
Unified CWE analysis tool for JSONL files.

This script combines the functionality of count_cwe.py and analyze_jsonl_cwe.py,
providing both simple CWE counting and detailed analysis including single/multi-CWE
sample statistics.

Modes:
1. Simple mode: Count CWE occurrences (default)
2. Detailed mode: Analyze single vs multi-CWE samples
3. Summary mode: Both simple and detailed statistics

Usage:
    # Simple CWE counting
    python analyze_cwe.py input.jsonl

    # Detailed analysis with single/multi-CWE breakdown
    python analyze_cwe.py input.jsonl --detailed

    # Save results to CSV
    python analyze_cwe.py input.jsonl --detailed --output cwe_stats.csv
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils import (
    read_jsonl,
    setup_script_logging,
    create_argument_parser,
    add_common_args,
    validate_file_exists,
    normalize_cwe
)


def count_cwe_simple(jsonl_path, verbose=False):
    """
    Simple CWE counting (original count_cwe.py functionality).

    Args:
        jsonl_path: Path to JSONL file
        verbose: If True, print progress messages

    Returns:
        Tuple of (cwe_counter, total_count)
    """
    logger = setup_script_logging(__name__, verbose=verbose)

    logger.info(f"Reading file: {jsonl_path}")

    cwe_counter = Counter()
    total_count = 0

    for item in read_jsonl(jsonl_path, verbose=verbose, skip_errors=True):
        cwe = item.get('cwe', item.get('CWE', 'Unknown'))
        if cwe:
            cwe = normalize_cwe(cwe) if cwe != 'Unknown' else cwe
        else:
            cwe = 'Unknown'

        cwe_counter[cwe] += 1
        total_count += 1

    logger.info(f"Processed {total_count:,} records")

    return cwe_counter, total_count


def analyze_cwe_detailed(jsonl_path, verbose=False):
    """
    Detailed CWE analysis (original analyze_jsonl_cwe.py functionality).

    Analyzes single vs multi-CWE samples.

    Args:
        jsonl_path: Path to JSONL file
        verbose: If True, print progress messages

    Returns:
        Dict of CWE statistics with 'total', 'single', 'multi' counts
    """
    logger = setup_script_logging(__name__, verbose=verbose)

    logger.info(f"Reading file: {jsonl_path}")

    cwe_stats = defaultdict(lambda: {'total': 0, 'single': 0, 'multi': 0})
    total_lines = 0
    skipped = 0

    for item in read_jsonl(jsonl_path, verbose=verbose, skip_errors=True):
        total_lines += 1

        # Get main CWE
        cwe = item.get('cwe', item.get('CWE'))
        if not cwe or str(cwe).lower() == 'unknown':
            skipped += 1
            continue

        # Normalize CWE
        cwe = normalize_cwe(cwe)

        # Check for other CWEs
        other_cwes = item.get('other_cwes', item.get('other CWEs', []))
        has_other_cwes = isinstance(other_cwes, list) and len(other_cwes) > 0

        # Update statistics
        cwe_stats[cwe]['total'] += 1
        if has_other_cwes:
            cwe_stats[cwe]['multi'] += 1
        else:
            cwe_stats[cwe]['single'] += 1

    logger.info(f"Processed {total_lines:,} records")
    if skipped > 0:
        logger.info(f"Skipped {skipped} records with unknown CWE")

    return dict(cwe_stats)


def print_simple_statistics(cwe_counter, total_count, top_n=10):
    """Print simple CWE count statistics."""
    print("\n" + "=" * 70)
    print(f"CWE Statistics (Total: {total_count:,} records)")
    print("=" * 70 + "\n")

    # Sort by CWE ID
    sorted_cwes = sorted(cwe_counter.items(), key=lambda x: x[0])

    for cwe, count in sorted_cwes:
        percentage = (count / total_count) * 100 if total_count > 0 else 0
        print(f"{cwe:20s}: {count:6,} ({percentage:5.2f}%)")

    print("\n" + "=" * 70)
    print(f"Total unique CWEs: {len(cwe_counter)}")
    print("=" * 70)

    # Show top N most common
    print(f"\nTop {top_n} Most Common CWEs:")
    print("-" * 70)
    for cwe, count in cwe_counter.most_common(top_n):
        percentage = (count / total_count) * 100 if total_count > 0 else 0
        print(f"{cwe:20s}: {count:6,} ({percentage:5.2f}%)")


def print_detailed_statistics(cwe_stats, top_n=50):
    """Print detailed CWE statistics with single/multi breakdown."""
    # Sort by sample count
    sorted_cwes = sorted(cwe_stats.items(), key=lambda x: x[1]['total'], reverse=True)

    # Overall statistics
    total_samples = sum(s['total'] for s in cwe_stats.values())
    total_single = sum(s['single'] for s in cwe_stats.values())
    total_multi = sum(s['multi'] for s in cwe_stats.values())

    print("\n" + "=" * 80)
    print(" " * 25 + "CWE Analysis Report")
    print("=" * 80)

    print(f"\n【Overall Statistics】")
    print(f"  Unique CWE types: {len(cwe_stats)}")
    print(f"  Total samples: {total_samples:,}")
    print(f"  Single-CWE samples: {total_single:,} ({total_single/total_samples*100:.1f}%)")
    print(f"  Multi-CWE samples: {total_multi:,} ({total_multi/total_samples*100:.1f}%)")

    # Detailed breakdown
    print(f"\n【Detailed CWE Statistics】(Top {top_n} by sample count)")
    print("-" * 80)
    print(f"{'CWE':<15} {'Total':>10} {'Single':>10} {'Multi':>10} {'Single %':>10}")
    print("-" * 80)

    for cwe, stats in sorted_cwes[:top_n]:
        total = stats['total']
        single = stats['single']
        multi = stats['multi']
        single_ratio = single / total * 100 if total > 0 else 0

        print(f"{cwe:<15} {total:>10,} {single:>10,} {multi:>10,} {single_ratio:>9.1f}%")

    if len(sorted_cwes) > top_n:
        print(f"\n... and {len(sorted_cwes) - top_n} more CWEs")

    print("-" * 80)

    # Distribution analysis
    print(f"\n【Single-CWE Ratio Distribution】")
    print("-" * 80)
    ratio_ranges = [
        (0, 20, "0-20%"),
        (20, 40, "20-40%"),
        (40, 60, "40-60%"),
        (60, 80, "60-80%"),
        (80, 100, "80-100%"),
        (100, 101, "100%")
    ]

    for low, high, label in ratio_ranges:
        count = sum(
            1 for stats in cwe_stats.values()
            if low <= (stats['single'] / stats['total'] * 100) < high
        )
        print(f"  {label:<15} {count:>5} CWEs")

    print("=" * 80)


def save_simple_csv(cwe_counter, total_count, output_path):
    """Save simple CWE counts to CSV."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['cwe', 'count', 'percentage'])

        sorted_cwes = sorted(cwe_counter.items(), key=lambda x: x[1], reverse=True)

        for cwe, count in sorted_cwes:
            percentage = (count / total_count) * 100 if total_count > 0 else 0
            writer.writerow([cwe, count, f"{percentage:.2f}"])

    print(f"\nResults saved to: {output_path}")


def save_detailed_csv(cwe_stats, output_path):
    """Save detailed CWE statistics to CSV."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'cwe', 'total_samples', 'single_cwe_samples',
            'multi_cwe_samples', 'single_ratio'
        ])

        sorted_cwes = sorted(cwe_stats.items(), key=lambda x: x[1]['total'], reverse=True)

        for cwe, stats in sorted_cwes:
            total = stats['total']
            single = stats['single']
            multi = stats['multi']
            single_ratio = single / total * 100 if total > 0 else 0

            writer.writerow([cwe, total, single, multi, f"{single_ratio:.2f}"])

    print(f"\nDetailed statistics saved to: {output_path}")


def main():
    parser = create_argument_parser(
        description='Analyze CWE statistics in JSONL files',
        epilog='''
Examples:
  # Simple CWE counting
  %(prog)s input.jsonl

  # Detailed analysis
  %(prog)s input.jsonl --detailed

  # Save to CSV
  %(prog)s input.jsonl --detailed --output stats.csv

  # Show more results
  %(prog)s input.jsonl --detailed --top 100
        '''
    )

    # Required arguments
    parser.add_argument(
        'input',
        type=validate_file_exists,
        help='Input JSONL file'
    )

    # Optional arguments
    parser.add_argument(
        '-d', '--detailed',
        action='store_true',
        help='Perform detailed analysis (single vs multi-CWE)'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Save results to CSV file'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=50,
        help='Number of top CWEs to display in detailed mode (default: 50)'
    )

    # Add common args
    add_common_args(parser, include_verbose=True)

    args = parser.parse_args()

    try:
        if args.detailed:
            # Detailed analysis
            cwe_stats = analyze_cwe_detailed(args.input, verbose=args.verbose)
            print_detailed_statistics(cwe_stats, top_n=args.top)

            if args.output:
                save_detailed_csv(cwe_stats, args.output)

        else:
            # Simple counting
            cwe_counter, total_count = count_cwe_simple(args.input, verbose=args.verbose)
            print_simple_statistics(cwe_counter, total_count)

            if args.output:
                save_simple_csv(cwe_counter, total_count, args.output)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
