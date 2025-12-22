"""Pipeline integration for transformation step."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from ..transform.transformer import transform_to_benchmark

logger = logging.getLogger(__name__)


@dataclass
class TransformResult:
    """Result of transformation step."""

    success: bool
    output_path: Optional[Path] = None
    total_entries: int = 0
    total_cwds: int = 0
    stats: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def run_transform_step(
    cleaned_dir: Path,
    output_path: Path,
    cwd_mapping_file: Path,
    datasets_dir: Path,
    cache_dir: Path,
    config: Dict[str, Any]
) -> TransformResult:
    """
    Run transformation step on cleaned data.

    Args:
        cleaned_dir: Directory containing cleaned CSV files
        output_path: Output benchmark JSON file path
        cwd_mapping_file: Path to CWE-to-CWD mapping file
        datasets_dir: Root datasets directory
        cache_dir: Cache directory
        config: Transform configuration

    Returns:
        TransformResult with statistics
    """
    try:
        # Get GitHub token from environment
        github_token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')

        # Extract config
        clustering_config = config.get('clustering', {})
        max_samples = clustering_config.get('max_samples_per_group', 300)
        method = clustering_config.get('method', 'kmeans')

        url_config = config.get('url_validation', {})
        validate_urls = url_config.get('enabled', False)

        # Run transformation
        stats = transform_to_benchmark(
            cleaned_dir=cleaned_dir,
            output_path=output_path,
            cwd_mapping_file=cwd_mapping_file,
            datasets_dir=datasets_dir,
            cache_dir=cache_dir,
            max_samples_per_group=max_samples,
            clustering_method=method,
            validate_urls=validate_urls,
            github_token=github_token
        )

        return TransformResult(
            success=True,
            output_path=output_path,
            total_entries=stats['total_entries'],
            total_cwds=stats['total_cwds'],
            stats=stats
        )

    except Exception as e:
        logger.error(f"Transform step failed: {e}", exc_info=True)
        return TransformResult(
            success=False,
            error=str(e)
        )
