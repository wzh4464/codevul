#!/usr/bin/env python3
"""Clean review_message field in existing benchmark JSON files."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.transform.review_cleaner import clean_review_message

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def clean_benchmark_file(input_path: Path, output_path: Path) -> dict:
    """Clean review_message in benchmark JSON file."""
    logger.info(f"Loading {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = {'total': 0, 'cleaned': 0, 'already_clean': 0, 'no_message': 0}

    for language, cwd_dict in data.items():
        for cwd_id, entries in cwd_dict.items():
            for entry in entries:
                stats['total'] += 1

                if 'review_message' not in entry or not entry['review_message']:
                    stats['no_message'] += 1
                    continue

                original = entry['review_message']
                cleaned = clean_review_message(original)
                entry['review_message'] = cleaned

                if cleaned != original:
                    stats['cleaned'] += 1
                else:
                    stats['already_clean'] += 1

    logger.info(f"Writing to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return stats


def main():
    parser = argparse.ArgumentParser(description='Clean review_message in benchmark files')
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

    total_stats = {'total': 0, 'cleaned': 0, 'already_clean': 0, 'no_message': 0}

    for input_file in benchmark_files:
        output_file = output_dir / input_file.name
        logger.info(f"\nProcessing {input_file.name}...")

        stats = clean_benchmark_file(input_file, output_file)

        for key in total_stats:
            total_stats[key] += stats[key]

        logger.info(f"  Total: {stats['total']}")
        logger.info(f"  Cleaned: {stats['cleaned']}")
        logger.info(f"  Already clean: {stats['already_clean']}")
        logger.info(f"  No message: {stats['no_message']}")

    logger.info(f"\n{'='*60}")
    logger.info("TOTAL STATISTICS")
    logger.info(f"  Total entries: {total_stats['total']}")
    logger.info(f"  Cleaned: {total_stats['cleaned']}")
    logger.info(f"  Already clean: {total_stats['already_clean']}")
    logger.info(f"  No message: {total_stats['no_message']}")


if __name__ == '__main__':
    main()
