#!/usr/bin/env python3
"""
Optimize existing benchmark JSON/JSONL files using CodeOptimizer.

This script processes files to reduce their size by keeping only the code
that is relevant to the changes between vulnerable and benign versions.

- For .jsonl files, it uses a full streaming approach (reads, processes,
  and writes in batches) to handle very large files with low memory usage.
- For .json files, due to their nested dictionary structure, the entire
  file is read into memory first. A true streaming approach for this
  format would require a dedicated library.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Iterator

# Add src to path to allow importing CodeOptimizer
sys.path.append(str(Path(__file__).parent.parent / 'src'))
from review.code_optimizer import CodeOptimizer

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def process_jsonl_stream(input_path: Path, output_path: Path, optimizer: CodeOptimizer, batch_size: int):
    """
    Reads a JSONL file in a streaming fashion, optimizes entries in batches,
    and writes them to a new file. This is memory-efficient.
    """
    logging.info(f"Processing {input_path} with batch size {batch_size} (streaming)...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    batch = []
    processed_count = 0
    total_lines = 0

    try:
        with open(input_path, 'r', encoding='utf-8') as f_in, \
             open(output_path, 'w', encoding='utf-8') as f_out:
            
            for line in f_in:
                total_lines += 1
                try:
                    entry = json.loads(line)
                    optimizer.optimize_entry(entry)
                    batch.append(entry)
                    
                    if len(batch) >= batch_size:
                        for item in batch:
                            f_out.write(json.dumps(item, ensure_ascii=False) + '\n')
                        processed_count += len(batch)
                        logging.info(f"  ... processed {processed_count} entries")
                        batch = [] # Clear memory for the next batch
                
                except json.JSONDecodeError:
                    logging.warning(f"Skipping invalid JSON line #{total_lines} in {input_path}")
                    continue

            # Write any remaining items in the last batch
            if batch:
                for item in batch:
                    f_out.write(json.dumps(item, ensure_ascii=False) + '\n')
                processed_count += len(batch)
        
        logging.info(f"Successfully wrote {processed_count} optimized entries to {output_path}")

    except Exception as e:
        logging.error(f"Failed to process {input_path}: {e}", exc_info=True)


def process_json_in_memory(input_path: Path, output_path: Path, optimizer: CodeOptimizer):
    """
    Reads a JSON file into memory, optimizes each entry, and writes to a new file.
    Warning: This is not a streaming method and can consume significant memory for large files.
    """
    logging.info(f"Processing {input_path} (loading into memory)...")
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        processed_count = 0
        # The structure can be a list of entries or a nested dict (lang -> cwe -> entries)
        if isinstance(data, list):
            for entry in data:
                optimizer.optimize_entry(entry)
                processed_count += 1
        elif isinstance(data, dict):
            for lang, cwe_dict in data.items():
                if isinstance(cwe_dict, dict):
                    for cwe, entries in cwe_dict.items():
                        if isinstance(entries, list):
                            for entry in entries:
                                optimizer.optimize_entry(entry)
                                processed_count += 1

        # Write the optimized data
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Successfully wrote {processed_count} optimized entries to {output_path}")

    except Exception as e:
        logging.error(f"Failed to process {input_path}: {e}", exc_info=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'input_path',
        type=Path,
        help='Input file or directory containing JSON/JSONL benchmark files.',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        required=True,
        help='Directory to save the optimized files.',
    )
    parser.add_argument(
        '--context-lines',
        type=int,
        default=5,
        help='Number of context lines to keep around changes.',
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Number of entries to process in a batch for .jsonl files (streaming mode).',
    )
    args = parser.parse_args()

    if not args.input_path.exists():
        logging.error(f"Input path does not exist: {args.input_path}")
        sys.exit(1)

    optimizer = CodeOptimizer(context_lines=args.context_lines)

    if args.input_path.is_file():
        if args.input_path.suffix not in ['.json', '.jsonl']:
            logging.error("Input file must be a .json or .jsonl file.")
            sys.exit(1)
        
        output_file = args.output_dir / args.input_path.name
        if args.input_path.suffix == '.jsonl':
            process_jsonl_stream(args.input_path, output_file, optimizer, args.batch_size)
        else:
            process_json_in_memory(args.input_path, output_file, optimizer)

    elif args.input_path.is_dir():
        # Process JSONL files first with streaming
        logging.info("--- Processing JSONL files (streaming) ---")
        jsonl_files = sorted(args.input_path.rglob('*.jsonl'))
        for file_path in jsonl_files:
            relative_path = file_path.relative_to(args.input_path)
            output_file = args.output_dir / relative_path
            process_jsonl_stream(file_path, output_file, optimizer, args.batch_size)

        # Process JSON files
        logging.info("--- Processing JSON files (in-memory) ---")
        json_files = sorted(args.input_path.rglob('*.json'))
        for file_path in json_files:
            relative_path = file_path.relative_to(args.input_path)
            output_file = args.output_dir / relative_path
            process_json_in_memory(file_path, output_file, optimizer)
    
    logging.info("Optimization complete.")

if __name__ == '__main__':
    main()
