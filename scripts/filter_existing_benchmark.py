#!/usr/bin/env python3
"""Filter existing benchmark JSON files to remove multi-function samples and comments."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.transform.function_counter import is_single_function
from src.transform.comment_remover import remove_comments
from src.transform.review_cleaner import clean_review_message

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def filter_benchmark_file(input_path: Path, output_path: Path, do_remove_comments: bool = True, require_lines: bool = False) -> dict:
    """
    Filter a benchmark JSON file to keep only single-function samples.
    Also removes comments from code if enabled.

    Structure: {language: {CWD/CWE: [entries...]}}

    Returns statistics dict.
    """
    logger.info(f"Loading {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = {
        'total_input': 0,
        'kept': 0,
        'filtered_benign_multi': 0,
        'filtered_vulnerable_multi': 0,
        'filtered_both_multi': 0,
        'filtered_no_lines': 0,
    }

    filtered_data = {}

    for language, cwd_dict in data.items():
        filtered_data[language] = {}

        for cwd_id, entries in cwd_dict.items():
            filtered_entries = []

            for entry in entries:
                stats['total_input'] += 1

                # Get code from benign and vulnerable
                benign_code = entry.get('benign_code', {}).get('func')
                vulnerable_code = entry.get('vulnerable_code', {}).get('func')

                # Check if single function
                benign_ok = benign_code is None or is_single_function(benign_code, language)
                vulnerable_ok = vulnerable_code is None or is_single_function(vulnerable_code, language)

                if benign_ok and vulnerable_ok:
                    # Check lines requirement
                    if require_lines:
                        bl = entry.get('benign_code', {}).get('lines', [])
                        vl = entry.get('vulnerable_code', {}).get('lines', [])
                        if not bl and not vl:
                            stats['filtered_no_lines'] += 1
                            continue

                    # Remove comments if enabled
                    if do_remove_comments:
                        # Remove comments from all code fields
                        if entry.get('benign_code'):
                            bc = entry['benign_code']
                            if bc.get('context'):
                                bc['context'] = remove_comments(bc['context'], language)
                            if bc.get('class'):
                                bc['class'] = remove_comments(bc['class'], language)
                            if bc.get('func'):
                                bc['func'] = remove_comments(bc['func'], language)

                        if entry.get('vulnerable_code'):
                            vc = entry['vulnerable_code']
                            if vc.get('context'):
                                vc['context'] = remove_comments(vc['context'], language)
                            if vc.get('class'):
                                vc['class'] = remove_comments(vc['class'], language)
                            if vc.get('func'):
                                vc['func'] = remove_comments(vc['func'], language)

                        # Clean review_message
                        if entry.get('review_message'):
                            entry['review_message'] = clean_review_message(entry['review_message'])

                    filtered_entries.append(entry)
                    stats['kept'] += 1
                elif not benign_ok and not vulnerable_ok:
                    stats['filtered_both_multi'] += 1
                elif not benign_ok:
                    stats['filtered_benign_multi'] += 1
                else:
                    stats['filtered_vulnerable_multi'] += 1

                # Progress logging
                if stats['total_input'] % 10000 == 0:
                    logger.info(f"Processed {stats['total_input']} entries...")

            # Only keep CWD if it has entries
            if filtered_entries:
                filtered_data[language][cwd_id] = filtered_entries

        # Remove empty language dicts
        if not filtered_data[language]:
            del filtered_data[language]

    # Write output
    logger.info(f"Writing {stats['kept']} entries to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=2, ensure_ascii=False)

    return stats


def main():
    parser = argparse.ArgumentParser(description='Filter benchmark files for single-function samples and remove comments')
    parser.add_argument('input_dir', type=Path, help='Directory containing benchmark JSON files')
    parser.add_argument('--output-dir', type=Path, help='Output directory (default: input_dir/filtered)')
    parser.add_argument('--no-remove-comments', action='store_true', help='Skip comment removal')
    parser.add_argument('--require-lines', action='store_true', help='Remove entries without lines')
    args = parser.parse_args()

    input_dir = args.input_dir
    output_dir = args.output_dir or input_dir / 'filtered'
    output_dir.mkdir(parents=True, exist_ok=True)
    do_remove_comments = not args.no_remove_comments
    require_lines = args.require_lines

    # Find benchmark files
    benchmark_files = list(input_dir.glob('benchmark_*.json'))
    if not benchmark_files:
        logger.error(f"No benchmark_*.json files found in {input_dir}")
        sys.exit(1)

    logger.info(f"Found {len(benchmark_files)} benchmark files to process")
    logger.info(f"Remove comments: {do_remove_comments}")
    logger.info(f"Require lines: {require_lines}")

    total_stats = {
        'total_input': 0,
        'kept': 0,
        'filtered_benign_multi': 0,
        'filtered_vulnerable_multi': 0,
        'filtered_both_multi': 0,
        'filtered_no_lines': 0,
    }

    for input_file in benchmark_files:
        output_file = output_dir / input_file.name
        logger.info(f"\nProcessing {input_file.name}...")

        stats = filter_benchmark_file(input_file, output_file, do_remove_comments, require_lines)

        # Accumulate stats
        for key in total_stats:
            total_stats[key] += stats[key]

        # Print file stats
        logger.info(f"  Input: {stats['total_input']}")
        logger.info(f"  Kept: {stats['kept']}")
        logger.info(f"  Filtered (benign multi): {stats['filtered_benign_multi']}")
        logger.info(f"  Filtered (vulnerable multi): {stats['filtered_vulnerable_multi']}")
        logger.info(f"  Filtered (both multi): {stats['filtered_both_multi']}")
        logger.info(f"  Filtered (no lines): {stats['filtered_no_lines']}")

    # Print total stats
    logger.info("\n" + "="*60)
    logger.info("TOTAL STATISTICS")
    logger.info("="*60)
    logger.info(f"Total input entries: {total_stats['total_input']}")
    logger.info(f"Total kept: {total_stats['kept']}")
    logger.info(f"Total filtered: {total_stats['total_input'] - total_stats['kept']}")
    logger.info(f"  - Benign multi-function: {total_stats['filtered_benign_multi']}")
    logger.info(f"  - Vulnerable multi-function: {total_stats['filtered_vulnerable_multi']}")
    logger.info(f"  - Both multi-function: {total_stats['filtered_both_multi']}")
    logger.info(f"  - No lines: {total_stats['filtered_no_lines']}")
    logger.info(f"\nFiltered files saved to: {output_dir}")


if __name__ == '__main__':
    main()
