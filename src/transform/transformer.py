"""Main transformation orchestrator."""

from __future__ import annotations

import csv
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..utils.cwe_utils import (
    get_all_cwds_for_cwe,
    get_cwd_for_cwe,
    is_unknown_cwe,
    load_cwd_mapping,
    normalize_cwe,
)
from ..dataset.common import (
    ensure_https,
    load_url_cache,
    save_url_cache,
    validate_github_url,
)
from .code_extractor import extract_structure
from .cve_extractor import (
    extract_commit_hash_from_url,
    load_cvefixes_cve_mapping,
)
from .clustering import cluster_and_sample

logger = logging.getLogger(__name__)


def read_cleaned_csvs(
    cleaned_dir: Path,
    cwe_to_cwd_mapping: Dict[str, List[str]],
    url_cache: Dict[str, Dict[str, any]],
    commit_to_cve: Dict[str, str],
    validate_urls: bool = False,
    github_token: Optional[str] = None
) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    """
    Stream and transform entries from cleaned CSV files.

    Args:
        cleaned_dir: Directory containing cleaned CSV files
        cwe_to_cwd_mapping: CWE to CWD mapping dictionary
        url_cache: URL validation cache
        commit_to_cve: Commit hash to CVE ID mapping
        validate_urls: Whether to validate GitHub URLs
        github_token: GitHub API token for authentication

    Yields:
        Tuples of (language, cwd, entry_dict)
    """
    csv_files = sorted(cleaned_dir.glob('*.csv'))

    total_read = 0
    filtered_cwe = 0
    filtered_cwd = 0
    filtered_url = 0
    yielded = 0

    for csv_file in csv_files:
        dataset_name = csv_file.stem

        # Skip excluded datasets
        if dataset_name in ('crossvul', 'bigvul'):
            logger.info(f"Skipping excluded dataset: {dataset_name}")
            continue

        logger.info(f"Processing {dataset_name}.csv...")

        with open(csv_file, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)

            for row in reader:
                total_read += 1

                # Extract fields
                cwe_raw = row.get('cwe', '').strip()
                code_before = row.get('code_before', '').strip()
                code_after = row.get('code_after', '').strip()
                commit_url = row.get('commit_url', '').strip()
                language = row.get('language', '').strip()

                # Parse pipe-separated CWEs
                cwe_list = [normalize_cwe(c.strip()) for c in cwe_raw.split('|') if c.strip()]
                # Filter out Unknown CWEs
                cwe_list = [c for c in cwe_list if c and not is_unknown_cwe(c)]

                if not cwe_list:
                    filtered_cwe += 1
                    continue

                # Separate primary CWE and other CWEs
                normalized_cwe = cwe_list[0]
                other_cwes = cwe_list[1:] if len(cwe_list) > 1 else []

                # Map primary CWE to CWD
                cwd = get_cwd_for_cwe(normalized_cwe, cwe_to_cwd_mapping)

                if not cwd:
                    filtered_cwd += 1
                    continue

                # Map other_CWEs to other_CWDs (exclude primary CWD)
                other_cwds = []
                for other_cwe in other_cwes:
                    other_cwd = get_cwd_for_cwe(other_cwe, cwe_to_cwd_mapping)
                    # Only include if: 1) CWD exists, 2) not same as primary CWD, 3) not already in list
                    if other_cwd and other_cwd != cwd and other_cwd not in other_cwds:
                        other_cwds.append(other_cwd)

                # Validate GitHub URL (if enabled)
                if validate_urls and commit_url:
                    commit_url_https = ensure_https(commit_url)
                    if commit_url_https and not validate_github_url(
                        commit_url_https, url_cache, github_token=github_token
                    ):
                        filtered_url += 1
                        continue
                    commit_url = commit_url_https

                # Extract code structures
                benign_structure = extract_structure(code_after, language)
                vulnerable_structure = extract_structure(code_before, language)

                # Extract CVE ID (if available from CVEfixes)
                cve_id = None
                if commit_url:
                    commit_hash = extract_commit_hash_from_url(commit_url)
                    if commit_hash:
                        cve_id = commit_to_cve.get(commit_hash)

                # Build entry
                entry = {
                    'benign_code': {
                        'context': benign_structure['context'],
                        'class': benign_structure['class'],
                        'func': benign_structure['func'],
                        'lines': []
                    },
                    'vulnerable_code': {
                        'context': vulnerable_structure['context'],
                        'class': vulnerable_structure['class'],
                        'func': vulnerable_structure['func'],
                        'lines': []
                    },
                    'source': dataset_name,
                    'commit_url': commit_url if commit_url else None,
                    'CWE': normalized_cwe,
                    'other_CWEs': other_cwes,
                    'other_CWDs': other_cwds,
                    'CVE': cve_id
                }

                yielded += 1
                yield (language, cwd, entry)

                # Log progress periodically
                if total_read % 1000 == 0:
                    logger.info(f"  Processed {total_read} rows, yielded {yielded} entries")

    # Final statistics
    logger.info(f"\n{'='*70}")
    logger.info(f"Transformation Statistics:")
    logger.info(f"  Total read:           {total_read:,}")
    logger.info(f"  Filtered (CWE):       {filtered_cwe:,}")
    logger.info(f"  Filtered (CWD):       {filtered_cwd:,}")
    logger.info(f"  Filtered (URL):       {filtered_url:,}")
    logger.info(f"  Final yielded:        {yielded:,}")
    logger.info(f"{'='*70}\n")


def transform_to_benchmark(
    cleaned_dir: Path,
    output_path: Path,
    cwd_mapping_file: Path,
    datasets_dir: Path,
    cache_dir: Path,
    max_samples_per_group: int = 300,
    clustering_method: str = 'kmeans',
    validate_urls: bool = False,
    github_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Transform cleaned CSVs to benchmark JSON format.

    Args:
        cleaned_dir: Directory containing cleaned CSV files
        output_path: Output benchmark JSON file path
        cwd_mapping_file: Path to CWE-to-CWD mapping file (collect.json)
        datasets_dir: Root datasets directory (for CVEfixes)
        cache_dir: Cache directory for URL cache and embeddings
        max_samples_per_group: Maximum samples per (language, CWD) group
        clustering_method: Clustering method ('kmeans' or 'stratified')
        validate_urls: Whether to validate GitHub URLs
        github_token: GitHub token for API authentication

    Returns:
        Statistics dictionary
    """
    # Load CWE to CWD mapping
    logger.info("Loading CWE to CWD mapping...")
    cwe_to_cwd_mapping = load_cwd_mapping(cwd_mapping_file)
    logger.info(f"Loaded {len(cwe_to_cwd_mapping)} CWE to CWD mappings")

    # Load URL cache
    url_cache_path = cache_dir / "url_cache.json"
    logger.info("Loading URL validation cache...")
    url_cache = load_url_cache(url_cache_path)
    logger.info(f"Loaded {len(url_cache)} cached URL validations")

    # Load CVE mapping from CVEfixes
    logger.info("Loading CVE mapping from CVEfixes...")
    commit_to_cve = load_cvefixes_cve_mapping(datasets_dir)
    if commit_to_cve:
        logger.info(f"Loaded CVE mapping for {len(commit_to_cve)} commits")
    else:
        logger.info("CVE mapping not loaded (CVEfixes not available)")

    # Stream and group entries by (language, CWD)
    logger.info("Streaming and transforming CSV files...")
    grouped_entries = defaultdict(list)

    # Log GitHub token status
    if validate_urls:
        if github_token:
            logger.info("Using GitHub token for authentication (5000 req/hour limit)")
        else:
            logger.warning("No GitHub token provided (60 req/hour limit)")
            logger.warning("Set GITHUB_TOKEN env var for higher limits")

    for language, cwd, entry in read_cleaned_csvs(
        cleaned_dir,
        cwe_to_cwd_mapping,
        url_cache,
        commit_to_cve,
        validate_urls=validate_urls,
        github_token=github_token
    ):
        grouped_entries[(language, cwd)].append(entry)

    logger.info(f"Grouped into {len(grouped_entries)} (language, CWD) combinations")

    # Save URL cache
    if validate_urls:
        logger.info("Saving URL validation cache...")
        save_url_cache(url_cache, url_cache_path)

    # Apply clustering/sampling for large groups
    logger.info("Applying clustering/sampling to large groups...")
    final_data = defaultdict(lambda: defaultdict(list))

    embeddings_cache_dir = cache_dir / "embeddings"
    embeddings_cache_dir.mkdir(parents=True, exist_ok=True)

    for (language, cwd), entries in sorted(grouped_entries.items()):
        logger.info(f"Processing {language} / {cwd}: {len(entries)} entries")

        if len(entries) > max_samples_per_group:
            # Need to cluster/sample
            # Use the primary CWE from the first entry for embedding lookup
            primary_cwe = entries[0]['CWE']
            selected_entries = cluster_and_sample(
                entries,
                max_samples_per_group,
                primary_cwe,
                embeddings_cache_dir,
                method=clustering_method
            )
        else:
            # Keep all entries
            selected_entries = entries

        final_data[language][cwd] = selected_entries
        logger.info(f"  Kept {len(selected_entries)} entries")

    # Convert defaultdict to regular dict for JSON serialization
    output_data = {
        lang: dict(cwd_dict)
        for lang, cwd_dict in final_data.items()
    }

    # Write output as compact JSON
    logger.info(f"Writing output to {output_path}...")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, separators=(',', ':'), ensure_ascii=False)

    # Calculate statistics
    stats = {
        'total_languages': len(output_data),
        'total_cwds': sum(len(cwd_dict) for cwd_dict in output_data.values()),
        'total_entries': sum(
            len(entries)
            for cwd_dict in output_data.values()
            for entries in cwd_dict.values()
        ),
        'by_language': {}
    }

    for language in sorted(output_data.keys()):
        lang_data = output_data[language]
        stats['by_language'][language] = {
            'cwds': len(lang_data),
            'entries': sum(len(entries) for entries in lang_data.values())
        }

    # Print statistics
    logger.info(f"\n{'='*70}")
    logger.info("Final Statistics:")
    for language in sorted(output_data.keys()):
        lang_data = output_data[language]
        total_entries = sum(len(entries) for entries in lang_data.values())
        logger.info(f"\n  Language: {language}")
        logger.info(f"    CWDs: {len(lang_data)}")
        logger.info(f"    Total entries: {total_entries}")

        # Show top CWDs
        cwd_counts = [(cwd, len(entries)) for cwd, entries in lang_data.items()]
        cwd_counts.sort(key=lambda x: x[1], reverse=True)

        logger.info(f"    Top 10 CWDs:")
        for cwd, count in cwd_counts[:10]:
            logger.info(f"      {cwd}: {count}")

    logger.info(f"{'='*70}")
    logger.info(f"Transformation complete! Output saved to: {output_path}")

    return stats
