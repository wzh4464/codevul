"""Dataset normalization step."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..dataset import NORMALIZERS

logger = logging.getLogger(__name__)


@dataclass
class NormalizeResult:
    """Result of normalization step."""

    dataset: str
    success: bool
    output_path: Optional[Path] = None
    rows_written: int = 0
    truncated: bool = False
    error: Optional[str] = None


def normalize_dataset(
    dataset_name: str,
    datasets_dir: Path,
    output_dir: Path,
    limit: Optional[int] = None
) -> NormalizeResult:
    """
    Normalize a single dataset.

    Args:
        dataset_name: Name of dataset to normalize
        datasets_dir: Root directory containing raw datasets
        output_dir: Directory to write normalized CSV
        limit: Optional limit on number of rows

    Returns:
        NormalizeResult with status
    """
    if dataset_name not in NORMALIZERS:
        return NormalizeResult(
            dataset=dataset_name,
            success=False,
            error=f"Unknown dataset: {dataset_name}"
        )

    try:
        normalizer = NORMALIZERS[dataset_name]
        logger.info(f"Normalizing {dataset_name}...")

        result = normalizer(
            root=datasets_dir,  # Pass datasets dir as root
            outdir=output_dir,
            limit=limit
        )

        if result is None:
            return NormalizeResult(
                dataset=dataset_name,
                success=False,
                error="Normalizer returned None"
            )

        output_path, rows_written, truncated = result

        logger.info(
            f"{dataset_name}: wrote {rows_written} rows to {output_path}"
            f"{' (truncated)' if truncated else ''}"
        )

        return NormalizeResult(
            dataset=dataset_name,
            success=True,
            output_path=output_path,
            rows_written=rows_written,
            truncated=truncated
        )

    except Exception as e:
        logger.error(f"Failed to normalize {dataset_name}: {e}", exc_info=True)
        return NormalizeResult(
            dataset=dataset_name,
            success=False,
            error=str(e)
        )


def normalize_all(
    datasets_dir: Path,
    output_dir: Path,
    dataset_names: Optional[List[str]] = None,
    parallel: bool = True,
    max_workers: int = 4,
    limit: Optional[int] = None
) -> Dict[str, NormalizeResult]:
    """
    Normalize all or specified datasets.

    Args:
        datasets_dir: Root directory containing raw datasets
        output_dir: Directory to write normalized CSVs
        dataset_names: List of datasets to normalize, or None for all
        parallel: Whether to run in parallel
        max_workers: Number of parallel workers
        limit: Optional limit on rows per dataset

    Returns:
        Dictionary mapping dataset name to NormalizeResult
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if dataset_names is None:
        dataset_names = list(NORMALIZERS.keys())

    logger.info(f"Normalizing {len(dataset_names)} datasets: {', '.join(dataset_names)}")

    results = {}

    if parallel and len(dataset_names) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    normalize_dataset,
                    name,
                    datasets_dir,
                    output_dir,
                    limit
                ): name
                for name in dataset_names
            }

            for future in as_completed(futures):
                dataset_name = futures[future]
                try:
                    result = future.result()
                    results[dataset_name] = result
                except Exception as e:
                    logger.error(f"Exception normalizing {dataset_name}: {e}")
                    results[dataset_name] = NormalizeResult(
                        dataset=dataset_name,
                        success=False,
                        error=str(e)
                    )
    else:
        # Sequential processing
        for dataset_name in dataset_names:
            result = normalize_dataset(
                dataset_name,
                datasets_dir,
                output_dir,
                limit
            )
            results[dataset_name] = result

    # Summary
    successful = sum(1 for r in results.values() if r.success)
    total_rows = sum(r.rows_written for r in results.values())

    logger.info(f"Normalization complete: {successful}/{len(dataset_names)} successful, {total_rows} total rows")

    return results
