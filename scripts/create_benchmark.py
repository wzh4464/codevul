"""Create unified benchmark.json from standardized CSV files."""

from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

# Add src to path to allow importing CodeOptimizer
sys.path.append(str(Path(__file__).parent.parent / 'src'))
from review.code_optimizer import CodeOptimizer


# Increase CSV field size limit
csv.field_size_limit(sys.maxsize)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def extract_cwe_number(cwe_field: str) -> str | None:
    """Extract CWE number from the cwe field."""
    if not cwe_field:
        return None

    # Handle formats like "CWE-79", "CWE-89", or paths containing CWE numbers
    cwe_field = cwe_field.strip().upper()

    # Try to find CWE-XXX pattern
    import re
    match = re.search(r'CWE[-_]?(\d+)', cwe_field)
    if match:
        return f"CWE-{match.group(1)}"

    return cwe_field if cwe_field.startswith('CWE') else None


def create_benchmark_entry(
    row: Dict[str, str],
    source: str,
) -> Dict[str, Any]:
    """Create a benchmark entry from a CSV row."""
    code_before = row.get('code_before', '').strip()
    code_after = row.get('code_after', '').strip()

    return {
        'benign_lines': code_after.splitlines() if code_after else [],
        'vulnerable_lines': code_before.splitlines() if code_before else [],
        'context': None,  # Not available in current data
        'class': None,    # Not available in current data
        'func': None,     # Not available in current data
        'CWE': extract_cwe_number(row.get('cwe', '')),
        'source': source,
        'commit': row.get('commit_url', '') or None,
    }


def process_csv_file(csv_path: Path) -> List[Dict[str, Any]]:
    """Process a single CSV file and return benchmark entries."""
    entries = []
    source = csv_path.stem  # Use filename without extension as source

    logging.info(f"Processing {csv_path.name}...")

    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row_num, row in enumerate(reader, start=1):
                try:
                    entry = create_benchmark_entry(row, source)
                    entries.append(entry)
                except Exception as e:
                    logging.warning(
                        f"Skipping row {row_num} in {csv_path.name}: {e}"
                    )
                    continue

                if row_num % 100000 == 0:
                    logging.info(f"  Processed {row_num:,} rows from {csv_path.name}")

        logging.info(f"  Completed {csv_path.name}: {len(entries):,} entries")
    except Exception as e:
        logging.error(f"Error processing {csv_path.name}: {e}")

    return entries


def organize_by_language_and_cwe(
    entries: List[Dict[str, Any]],
    language: str,
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Organize entries by language and CWE number."""
    result: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    # Normalize language name
    if not language:
        language = 'Unknown'
    lang = language.strip().lower()
    if lang in ['c', 'cpp', 'c++']:
        lang_key = 'C/C++'
    elif lang in ['java']:
        lang_key = 'Java'
    elif lang in ['python', 'py']:
        lang_key = 'Python'
    elif lang in ['javascript', 'js']:
        lang_key = 'JavaScript'
    elif lang in ['php']:
        lang_key = 'PHP'
    else:
        lang_key = lang.capitalize()

    for entry in entries:
        cwe = entry.get('CWE')
        if not cwe:
            cwe = 'Unknown'

        if lang_key not in result:
            result[lang_key] = {}
        if cwe not in result[lang_key]:
            result[lang_key][cwe] = []

        result[lang_key][cwe].append(entry)

    return result


def merge_benchmarks(
    benchmark: Dict[str, Dict[str, List[Dict[str, Any]]]],
    new_data: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> None:
    """Merge new data into existing benchmark."""
    for lang, cwe_dict in new_data.items():
        if lang not in benchmark:
            benchmark[lang] = {}
        for cwe, entries in cwe_dict.items():
            if cwe not in benchmark[lang]:
                benchmark[lang][cwe] = []
            benchmark[lang][cwe].extend(entries)


def create_benchmark_json(
    standardized_dir: Path,
    output_path: Path,
    optimize: bool = False,
) -> None:
    """Create benchmark.json from all standardized CSV files."""
    logging.info("Starting benchmark.json creation")
    if optimize:
        logging.info("Code optimization is ENABLED")

    benchmark: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    optimizer = CodeOptimizer() if optimize else None

    # Process all CSV files in standardized directory
    csv_files = sorted(standardized_dir.glob('*.csv'))

    if not csv_files:
        logging.error(f"No CSV files found in {standardized_dir}")
        return

    logging.info(f"Found {len(csv_files)} CSV files to process")

    for csv_file in csv_files:
        logging.info(f"Processing {csv_file.name}...")

        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                row_count = 0

                for row in reader:
                    row_count += 1
                    language = row.get('language', 'Unknown')
                    entry = create_benchmark_entry(row, csv_file.stem)

                    if optimizer:
                        code_before = row.get('code_before', '')
                        code_after = row.get('code_after', '')
                        result = optimizer.optimize_code_pair(code_before, code_after)
                        if result.get('optimized'):
                            entry['vulnerable_lines'] = result['vulnerable_code']
                            entry['benign_lines'] = result['benign_code']
                            entry['_optimization'] = {
                                'enabled': True,
                                'reduction_ratio': result.get('reduction_ratio'),
                                'original_size': result.get('original_size'),
                                'optimized_size': result.get('optimized_size'),
                            }

                    # Organize by language and CWE
                    organized = organize_by_language_and_cwe([entry], language)
                    merge_benchmarks(benchmark, organized)

                    if row_count % 100000 == 0:
                        logging.info(f"  Processed {row_count:,} rows from {csv_file.name}")

                logging.info(f"  Completed {csv_file.name}: {row_count:,} rows")
        except Exception as e:
            logging.error(f"Error processing {csv_file.name}: {e}")
            continue

    # Write output
    logging.info(f"Writing benchmark.json to {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(benchmark, f, indent=2, ensure_ascii=False)

    # Print summary statistics
    logging.info("Benchmark creation complete!")
    logging.info(f"\nSummary:")
    logging.info(f"  Total languages: {len(benchmark)}")

    for lang, cwe_dict in sorted(benchmark.items()):
        total_entries = sum(len(entries) for entries in cwe_dict.values())
        logging.info(f"  {lang}: {len(cwe_dict)} CWEs, {total_entries:,} entries")


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--standardized-dir',
        type=Path,
        default=Path('clean/standardized'),
        help='Directory containing standardized CSV files',
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('benchmark.json'),
        help='Output path for benchmark.json',
    )
    parser.add_argument(
        '--optimize',
        action='store_true',
        help='Enable code optimization to reduce benchmark size.',
    )

    args = parser.parse_args()

    if not args.standardized_dir.exists():
        logging.error(f"Directory not found: {args.standardized_dir}")
        return

    create_benchmark_json(args.standardized_dir, args.output, args.optimize)


if __name__ == '__main__':
    main()
