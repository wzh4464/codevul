"""Sample generation step."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


def generate_sample(
    dataset_name: str,
    entries: List[Dict[str, Any]],
    output_dir: Path
) -> Path:
    """
    Generate a sample JSON file for a dataset.

    Args:
        dataset_name: Name of the dataset
        entries: List of benchmark entries from this dataset
        output_dir: Directory to write sample file

    Returns:
        Path to generated sample file
    """
    if not entries:
        raise ValueError(f"No entries for dataset {dataset_name}")

    # Select first entry as sample
    entry = entries[0]

    # Extract metadata
    language = None
    cwd = None
    cwe = entry.get('CWE', '')

    # Try to infer from benchmark structure
    # Entries are nested as benchmark[language][cwd][entries]
    # We'll get this from the entry itself

    sample = {
        "dataset": dataset_name,
        "sample_id": f"{dataset_name}_001",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "metadata": {
            "total_entries": len(entries),
            "language": entry.get('language', 'unknown'),
            "cwe": cwe,
        },
        "entry": entry
    }

    # Write sample file
    output_path = output_dir / f"{dataset_name}_sample.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sample, f, indent=2, ensure_ascii=False)

    logger.info(f"Generated sample for {dataset_name}: {output_path}")

    return output_path


def generate_samples(
    benchmark_path: Path,
    output_dir: Path,
    excluded_datasets: Set[str] = None
) -> Dict[str, Path]:
    """
    Generate sample files for all datasets in benchmark.

    Args:
        benchmark_path: Path to benchmark JSON file
        output_dir: Directory to write sample files
        excluded_datasets: Set of dataset names to exclude

    Returns:
        Dictionary mapping dataset name to sample file path
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if excluded_datasets is None:
        excluded_datasets = {'crossvul', 'bigvul'}

    logger.info(f"Generating samples from {benchmark_path}")
    logger.info(f"Excluding datasets: {excluded_datasets}")

    # Load benchmark
    with open(benchmark_path, 'r', encoding='utf-8') as f:
        benchmark = json.load(f)

    # Group entries by source dataset
    dataset_entries = {}

    # Benchmark structure: {language: {cwd: [entries]}}
    for language, cwds in benchmark.items():
        for cwd, entries in cwds.items():
            for entry in entries:
                source = entry.get('source', 'unknown')
                if source not in excluded_datasets:
                    if source not in dataset_entries:
                        dataset_entries[source] = []
                    dataset_entries[source].append(entry)

    # Generate samples
    samples = {}
    for dataset_name, entries in dataset_entries.items():
        try:
            sample_path = generate_sample(dataset_name, entries, output_dir)
            samples[dataset_name] = sample_path
        except Exception as e:
            logger.error(f"Failed to generate sample for {dataset_name}: {e}")

    logger.info(f"Generated {len(samples)} sample files")

    return samples
