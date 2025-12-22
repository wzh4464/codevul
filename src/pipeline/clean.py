"""Data cleaning step."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from ..cleaning import (
    CleaningStep,
    CleaningResult,
    LanguageFilter,
    CWEValidator,
    CodeValidator,
    URLValidator,
    Deduplicator,
)

logger = logging.getLogger(__name__)


@dataclass
class CleanResult:
    """Result of cleaning step."""

    success: bool
    step_results: List[CleaningResult] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def total_input(self) -> int:
        """Get initial input count."""
        if self.step_results:
            return self.step_results[0].input_count
        return 0

    @property
    def total_output(self) -> int:
        """Get final output count."""
        if self.step_results:
            return self.step_results[-1].output_count
        return 0

    @property
    def total_filtered(self) -> int:
        """Get total filtered count."""
        return self.total_input - self.total_output


def clean_dataset(
    input_path: Path,
    output_path: Path,
    cache_dir: Path,
    config: Dict
) -> CleanResult:
    """
    Clean a single dataset through all cleaning steps.

    Args:
        input_path: Path to normalized CSV
        output_path: Path to write cleaned CSV
        cache_dir: Cache directory
        config: Cleaning configuration

    Returns:
        CleanResult with all step results
    """
    try:
        # Create cleaning steps pipeline
        steps: List[CleaningStep] = [
            LanguageFilter(config.get('language_filter', {})),
            CWEValidator(config.get('cwe_validator', {})),
            CodeValidator(config.get('code_validator', {})),
            URLValidator(config.get('url_validator', {})),
            Deduplicator(config.get('deduplicator', {})),
        ]

        # Process through pipeline
        current_input = input_path
        results = []

        for i, step in enumerate(steps):
            # For intermediate steps, use temp files
            if i == len(steps) - 1:
                current_output = output_path
            else:
                current_output = cache_dir / f"temp_step_{i}_{input_path.name}"

            logger.info(f"Running {step.name} on {current_input.name}...")

            result = step.process(current_input, current_output, cache_dir)
            results.append(result)

            if not result.success:
                return CleanResult(success=False, step_results=results, error=result.error)

            # Next step's input is this step's output
            current_input = current_output

        logger.info(
            f"Cleaned {input_path.name}: {results[0].input_count} → {results[-1].output_count} "
            f"(filtered {results[0].input_count - results[-1].output_count})"
        )

        return CleanResult(success=True, step_results=results)

    except Exception as e:
        logger.error(f"Failed to clean {input_path}: {e}", exc_info=True)
        return CleanResult(success=False, error=str(e))


def clean_all(
    input_dir: Path,
    output_dir: Path,
    cache_dir: Path,
    config: Dict
) -> Dict[str, CleanResult]:
    """
    Clean all CSV files in input directory.

    Args:
        input_dir: Directory with normalized CSVs
        output_dir: Directory to write cleaned CSVs
        cache_dir: Cache directory
        config: Cleaning configuration

    Returns:
        Dictionary mapping filename to CleanResult
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    csv_files = list(input_dir.glob("*.csv"))
    logger.info(f"Cleaning {len(csv_files)} CSV files")

    results = {}

    for csv_file in csv_files:
        output_path = output_dir / csv_file.name
        result = clean_dataset(csv_file, output_path, cache_dir, config)
        results[csv_file.name] = result

    # Summary
    successful = sum(1 for r in results.values() if r.success)
    total_input = sum(r.total_input for r in results.values())
    total_output = sum(r.total_output for r in results.values())

    logger.info(
        f"Cleaning complete: {successful}/{len(csv_files)} files, "
        f"{total_input} → {total_output} rows "
        f"(filtered {total_input - total_output}, {(total_input - total_output)/total_input*100:.1f}%)"
    )

    return results
