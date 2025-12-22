"""Pipeline orchestrator - coordinates all steps."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from . import normalize, clean, sample
from . import transform

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Pipeline configuration."""

    # Paths
    datasets_dir: Path
    results_dir: Path
    cache_dir: Path

    # Options
    dataset_names: Optional[List[str]] = None
    normalize_parallel: bool = True
    normalize_workers: int = 4
    limit: Optional[int] = None

    # Cleaning config
    clean_config: Dict = field(default_factory=dict)

    # Transform config
    transform_config: Dict = field(default_factory=dict)

    # Sample config
    excluded_datasets: set = field(default_factory=lambda: {'crossvul', 'bigvul'})

    @classmethod
    def from_yaml(cls, config_path: Path, **overrides) -> PipelineConfig:
        """Load configuration from YAML file."""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Extract paths
        paths = config.get('paths', {})
        datasets_dir = Path(paths.get('datasets', 'datasets'))
        results_dir = Path(paths.get('results', 'results'))
        cache_dir = Path(paths.get('cache', 'results/cache'))

        # Extract pipeline config
        pipeline = config.get('pipeline', {})
        norm_config = pipeline.get('normalize', {})
        clean_config = pipeline.get('clean', {})
        transform_config = pipeline.get('transform', {})
        sample_config = pipeline.get('sample', {})

        # Extract dataset list
        datasets = config.get('datasets', {})
        active_datasets = datasets.get('active', None)

        return cls(
            datasets_dir=datasets_dir,
            results_dir=results_dir,
            cache_dir=cache_dir,
            dataset_names=active_datasets,
            normalize_parallel=norm_config.get('parallel', True),
            normalize_workers=norm_config.get('max_workers', 4),
            clean_config=clean_config,
            transform_config=transform_config,
            excluded_datasets=set(sample_config.get('excluded_datasets', ['crossvul', 'bigvul'])),
            **overrides
        )


@dataclass
class PipelineResult:
    """Result of pipeline execution."""

    success: bool
    duration: float
    steps_completed: List[str]
    normalize_results: Optional[Dict] = None
    clean_results: Optional[Dict] = None
    transform_result: Optional[any] = None
    sample_results: Optional[Dict] = None
    error: Optional[str] = None


class PipelineOrchestrator:
    """Orchestrates the complete benchmark pipeline."""

    def __init__(self, config: PipelineConfig):
        """
        Initialize orchestrator.

        Args:
            config: Pipeline configuration
        """
        self.config = config

    def run_normalize_step(self) -> Dict:
        """Run normalization step."""
        logger.info("=" * 60)
        logger.info("STEP 1: NORMALIZATION")
        logger.info("=" * 60)

        normalized_dir = self.config.results_dir / "normalized"

        results = normalize.normalize_all(
            datasets_dir=self.config.datasets_dir,
            output_dir=normalized_dir,
            dataset_names=self.config.dataset_names,
            parallel=self.config.normalize_parallel,
            max_workers=self.config.normalize_workers,
            limit=self.config.limit
        )

        return results

    def run_clean_step(self) -> Dict:
        """Run cleaning step."""
        logger.info("=" * 60)
        logger.info("STEP 2: CLEANING")
        logger.info("=" * 60)

        normalized_dir = self.config.results_dir / "normalized"
        cleaned_dir = self.config.results_dir / "cleaned"

        results = clean.clean_all(
            input_dir=normalized_dir,
            output_dir=cleaned_dir,
            cache_dir=self.config.cache_dir,
            config=self.config.clean_config
        )

        return results

    def run_transform_step(self):
        """Run transformation step."""
        logger.info("=" * 60)
        logger.info("STEP 3: TRANSFORMATION")
        logger.info("=" * 60)

        cleaned_dir = self.config.results_dir / "cleaned"
        benchmark_dir = self.config.results_dir / "benchmark"
        benchmark_path = benchmark_dir / "benchmark.json"

        # Get CWD mapping file path
        cwd_mapping_file = Path(self.config.transform_config.get('cwd_mapping_file', 'collect.json'))

        result = transform.run_transform_step(
            cleaned_dir=cleaned_dir,
            output_path=benchmark_path,
            cwd_mapping_file=cwd_mapping_file,
            datasets_dir=self.config.datasets_dir,
            cache_dir=self.config.cache_dir,
            config=self.config.transform_config
        )

        return result

    def run_sample_step(self) -> Dict:
        """Run sample generation step."""
        logger.info("=" * 60)
        logger.info("STEP 4: SAMPLE GENERATION")
        logger.info("=" * 60)

        benchmark_path = self.config.results_dir / "benchmark" / "benchmark.json"

        if not benchmark_path.exists():
            logger.warning(f"Benchmark file not found: {benchmark_path}")
            logger.warning("Skipping sample generation")
            return {}

        samples_dir = self.config.results_dir / "samples"

        results = sample.generate_samples(
            benchmark_path=benchmark_path,
            output_dir=samples_dir,
            excluded_datasets=self.config.excluded_datasets
        )

        return results

    def run_full_pipeline(self) -> PipelineResult:
        """Run the complete pipeline."""
        logger.info("Starting CodeVul Benchmark Pipeline")
        logger.info(f"Datasets: {self.config.datasets_dir}")
        logger.info(f"Output: {self.config.results_dir}")

        start_time = time.time()
        steps_completed = []

        try:
            # Step 1: Normalize
            normalize_results = self.run_normalize_step()
            steps_completed.append("normalize")

            # Check if any succeeded
            if not any(r.success for r in normalize_results.values()):
                raise RuntimeError("All normalization failed")

            # Step 2: Clean
            clean_results = self.run_clean_step()
            steps_completed.append("clean")

            # Check if any succeeded
            if not any(r.success for r in clean_results.values()):
                raise RuntimeError("All cleaning failed")

            # Step 3: Transform
            transform_result = self.run_transform_step()

            # Check if transform succeeded
            if transform_result and transform_result.success:
                steps_completed.append("transform")
            else:
                raise RuntimeError("Transform step failed")

            # Step 4: Sample (if benchmark exists)
            sample_results = self.run_sample_step()
            if sample_results:
                steps_completed.append("sample")

            duration = time.time() - start_time

            logger.info("=" * 60)
            logger.info("PIPELINE COMPLETE")
            logger.info(f"Duration: {duration:.1f}s")
            logger.info(f"Steps: {' → '.join(steps_completed)}")
            logger.info("=" * 60)

            return PipelineResult(
                success=True,
                duration=duration,
                steps_completed=steps_completed,
                normalize_results=normalize_results,
                clean_results=clean_results,
                transform_result=transform_result,
                sample_results=sample_results
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Pipeline failed: {e}", exc_info=True)

            return PipelineResult(
                success=False,
                duration=duration,
                steps_completed=steps_completed,
                error=str(e)
            )
