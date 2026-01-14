#!/usr/bin/env python3
"""Remove entries without lines from benchmark JSON files."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def filter_empty_lines(input_path: Path, output_path: Path) -> dict:
    """Remove entries without lines from benchmark file."""
    logger.info(f"Loading {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = {'total': 0, 'kept': 0, 'removed': 0}
    filtered_data = {}

    for language, cwd_dict in data.items():
        filtered_data[language] = {}

        for cwd_id, entries in cwd_dict.items():
            filtered_entries = []

            for entry in entries:
                stats['total'] += 1

                bl = entry.get('benign_code', {}).get('lines', [])
                vl = entry.get('vulnerable_code', {}).get('lines', [])

                if bl or vl:
                    filtered_entries.append(entry)
                    stats['kept'] += 1
                else:
                    stats['removed'] += 1

            if filtered_entries:
                filtered_data[language][cwd_id] = filtered_entries

        if not filtered_data[language]:
            del filtered_data[language]

    logger.info(f"Writing to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=2, ensure_ascii=False)

    return stats


def main():
    parser = argparse.ArgumentParser(description='Remove entries without lines')
    parser.add_argument('input_dir', type=Path, help='Directory containing benchmark JSON files')
    parser.add_argument('--output-dir', type=Path, help='Output directory (default: input_dir)')
    args = parser.parse_args()

    input_dir = args.input_dir
    output_dir = args.output_dir or input_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    benchmark_files = list(input_dir.glob('benchmark_*.json'))
    if not benchmark_files:
        logger.error(f"No benchmark_*.json files found in {input_dir}")
        sys.exit(1)

    logger.info(f"Found {len(benchmark_files)} benchmark files")

    total_stats = {'total': 0, 'kept': 0, 'removed': 0}

    for input_file in benchmark_files:
        output_file = output_dir / input_file.name
        logger.info(f"\nProcessing {input_file.name}...")

        stats = filter_empty_lines(input_file, output_file)

        for key in total_stats:
            total_stats[key] += stats[key]

        logger.info(f"  Total: {stats['total']}")
        logger.info(f"  Kept: {stats['kept']}")
        logger.info(f"  Removed: {stats['removed']}")

    logger.info(f"\n{'='*60}")
    logger.info("TOTAL STATISTICS")
    logger.info(f"  Total: {total_stats['total']}")
    logger.info(f"  Kept: {total_stats['kept']}")
    logger.info(f"  Removed: {total_stats['removed']}")


if __name__ == '__main__':
    main()
