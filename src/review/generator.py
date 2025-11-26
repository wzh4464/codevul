"""Core review generation logic."""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from collections import defaultdict

from .cwe_enricher import CWEEnricher
from .diff_generator import DiffGenerator
from .prompter import PromptFormatter
from .validator import ReviewValidator

# Import LLM client
import sys
sys.path.append(str(Path(__file__).parent.parent))
from client import create_default_client, create_meta_prompt_client

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Track review generation progress."""

    def __init__(self, progress_file: str, resume: bool = False):
        """Initialize progress tracker.

        Args:
            progress_file: Path to progress file
            resume: Whether to resume from existing progress
        """
        self.progress_file = Path(progress_file)
        self.completed_ids = set()
        self.count = 0

        if resume and self.progress_file.exists():
            self._load_progress()

    def _load_progress(self):
        """Load progress from file."""
        try:
            with open(self.progress_file, 'r') as f:
                data = json.load(f)
                self.completed_ids = set(data.get('completed_ids', []))
                self.count = data.get('count', 0)
                logger.info(f"Resumed with {self.count} completed entries")
        except Exception as e:
            logger.error(f"Failed to load progress: {e}")

    def mark_completed(self, entry_id: str):
        """Mark an entry as completed."""
        self.completed_ids.add(entry_id)
        self.count += 1

    def is_completed(self, entry_id: str) -> bool:
        """Check if entry is completed."""
        return entry_id in self.completed_ids

    def save(self):
        """Save progress to file."""
        try:
            data = {
                'completed_ids': list(self.completed_ids),
                'count': self.count,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.progress_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save progress: {e}")


class ReviewCache:
    """Cache for generated reviews."""

    def __init__(self, cache_dir: str):
        """Initialize cache.

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def make_key(self, entry: Dict) -> str:
        """Generate cache key for an entry.

        Args:
            entry: Entry dictionary

        Returns:
            Cache key string
        """
        # Use source, CWE, and code hash to create key
        source = entry.get('source', 'unknown')
        cwe = entry.get('CWE', 'unknown')

        # Simple hash of code
        vulnerable_code = str(entry.get('vulnerable_code', ''))
        code_hash = hash(vulnerable_code) % 1000000

        return f"{source}_{cwe}_{code_hash}"

    def get(self, key: str) -> Optional[Dict]:
        """Get cached review.

        Args:
            key: Cache key

        Returns:
            Cached review or None
        """
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache {key}: {e}")
        return None

    def set(self, key: str, review: Dict):
        """Save review to cache.

        Args:
            key: Cache key
            review: Review dictionary
        """
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(review, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache {key}: {e}")


class ReviewGenerator:
    """Generate AI-based review comments for vulnerability datasets."""

    def __init__(self, config_path: str = "config/review_config.yaml", resume: bool = False):
        """Initialize review generator.

        Args:
            config_path: Path to configuration file
            resume: Whether to resume from previous run
        """
        self.config = self._load_config(config_path)

        # Initialize components
        cwe_db_path = self.config.get('enrichment', {}).get('cwe_database_path', 'collect.json')
        self.cwe_enricher = CWEEnricher(cwe_db_path)
        self.diff_generator = DiffGenerator()
        self.prompter = PromptFormatter()
        self.validator = ReviewValidator(self.config)

        # Initialize LLM clients
        self.primary_client = self._create_primary_client()
        self.fallback_client = self._create_fallback_client()

        # Initialize cache and progress
        cache_dir = self.config.get('processing', {}).get('cache_dir', 'review_cache')
        progress_file = self.config.get('processing', {}).get('progress_file', 'review_progress.json')

        self.cache = ReviewCache(cache_dir)
        self.progress = ProgressTracker(progress_file, resume=resume)

        # Initialize parallel executor
        parallel_workers = self.config.get('processing', {}).get('parallel_workers', 16)
        self.executor = ThreadPoolExecutor(max_workers=parallel_workers)

        # Streaming output settings
        self.streaming_output = self.config.get('processing', {}).get('streaming_output', True)
        self.output_file = self.config.get('processing', {}).get('output_file', 'benchmark_with_reviews.json')

        # Statistics
        self.stats = {
            'total_processed': 0,
            'cache_hits': 0,
            'api_calls': 0,
            'failures': 0,
            'regenerations': 0
        }

        logger.info("ReviewGenerator initialized")

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file.

        Args:
            config_path: Path to config file

        Returns:
            Configuration dictionary
        """
        try:
            import yaml
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Return default config
            return {'llm': {}, 'processing': {}, 'validation': {}}

    def _create_primary_client(self):
        """Create primary LLM client."""
        try:
            # Use META_MODEL_NAME (Claude) for primary
            client = create_meta_prompt_client()
            logger.info(f"Primary client created: {client.__class__.__name__}")
            return client
        except Exception as e:
            logger.error(f"Failed to create primary client: {e}")
            return None

    def _create_fallback_client(self):
        """Create fallback LLM client."""
        try:
            # Use MODEL_NAME (GPT-4o) for fallback
            client = create_default_client()
            logger.info(f"Fallback client created: {client.__class__.__name__}")
            return client
        except Exception as e:
            logger.error(f"Failed to create fallback client: {e}")
            return None

    def generate_review_for_entry(
        self,
        entry: Dict[str, Any],
        language: str,
        cwd: str,
        idx: int
    ) -> Dict[str, Any]:
        """Generate review for a single entry.

        Args:
            entry: Entry dictionary
            language: Programming language
            cwd: CWD identifier
            idx: Entry index

        Returns:
            Review dictionary
        """
        entry_id = f"{language}/{cwd}/{idx}"

        # Check cache
        cache_key = self.cache.make_key(entry)
        cached_review = self.cache.get(cache_key)
        if cached_review:
            logger.debug(f"Cache hit for {entry_id}")
            self.stats['cache_hits'] += 1
            return cached_review

        # Get CWE info
        cwe_info = self.cwe_enricher.get_cwe_info(entry.get('CWE', ''))

        # Stage 1: Vulnerability Analysis
        vuln_analysis = self._generate_vulnerability_analysis(entry, cwe_info)
        if not vuln_analysis:
            logger.error(f"Failed vulnerability analysis for {entry_id}")
            return self._create_failed_review()

        # Stage 2: Fix Analysis
        fix_analysis = self._generate_fix_analysis(
            entry,
            vuln_analysis.get('summary', ''),
            vuln_analysis.get('severity', 'MEDIUM')
        )
        if not fix_analysis:
            logger.error(f"Failed fix analysis for {entry_id}")
            return self._create_failed_review()

        # Generate diff
        vulnerable_code = self.prompter._extract_code(entry, 'vulnerable')
        benign_code = self.prompter._extract_code(entry, 'benign')
        diff = self.diff_generator.generate_compact_diff(vulnerable_code, benign_code)

        # Stage 3: Code Review
        code_review = self._generate_code_review(
            entry,
            cwe_info,
            vuln_analysis.get('summary', ''),
            fix_analysis.get('summary', ''),
            vuln_analysis.get('severity', 'MEDIUM'),
            fix_analysis.get('fix_quality', 'FAIR'),
            diff
        )
        if not code_review:
            logger.error(f"Failed code review for {entry_id}")
            return self._create_failed_review()

        # Combine into full review
        review = {
            'vulnerability_analysis': vuln_analysis,
            'fix_analysis': fix_analysis,
            'code_review': code_review,
            'metadata': self._generate_metadata()
        }

        # Calculate confidence
        confidence = self.validator.calculate_confidence(review, entry)
        review['metadata']['confidence'] = confidence

        # Check if regeneration needed
        if self.config.get('processing', {}).get('enable_multi_pass', False):
            if self.validator.should_regenerate(review, entry):
                max_attempts = self.config.get('processing', {}).get('max_regeneration_attempts', 2)
                if self.stats.get(f'regen_{entry_id}', 0) < max_attempts:
                    logger.info(f"Regenerating review for {entry_id} (low confidence: {confidence})")
                    self.stats[f'regen_{entry_id}'] = self.stats.get(f'regen_{entry_id}', 0) + 1
                    self.stats['regenerations'] += 1
                    return self.generate_review_for_entry(entry, language, cwd, idx)

        # Cache the review
        self.cache.set(cache_key, review)

        return review

    def _generate_vulnerability_analysis(self, entry: Dict, cwe_info: Dict) -> Optional[Dict]:
        """Generate vulnerability analysis."""
        prompt = self.prompter.format_vulnerability_analysis_prompt(entry, cwe_info)

        response = self._call_llm(prompt)
        if not response:
            return None

        parsed = self.validator.parse_json_response(response)
        if not parsed:
            logger.warning("Failed to parse vulnerability analysis response")
            return None

        return parsed

    def _generate_fix_analysis(self, entry: Dict, vuln_summary: str, severity: str) -> Optional[Dict]:
        """Generate fix analysis."""
        prompt = self.prompter.format_fix_analysis_prompt(entry, vuln_summary, severity)

        response = self._call_llm(prompt)
        if not response:
            return None

        parsed = self.validator.parse_json_response(response)
        if not parsed:
            logger.warning("Failed to parse fix analysis response")
            return None

        return parsed

    def _generate_code_review(
        self,
        entry: Dict,
        cwe_info: Dict,
        vuln_summary: str,
        fix_summary: str,
        severity: str,
        fix_quality: str,
        diff: str
    ) -> Optional[Dict]:
        """Generate code review."""
        prompt = self.prompter.format_code_review_prompt(
            entry, cwe_info, vuln_summary, fix_summary, severity, fix_quality, diff
        )

        response = self._call_llm(prompt)
        if not response:
            return None

        parsed = self.validator.parse_json_response(response)
        if not parsed:
            logger.warning("Failed to parse code review response")
            return None

        return parsed

    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call LLM with fallback."""
        self.stats['api_calls'] += 1

        # Try primary client
        if self.primary_client:
            try:
                response = self.primary_client.generate(prompt, temperature=0.1)
                return response
            except Exception as e:
                logger.warning(f"Primary client failed: {e}, trying fallback")

        # Try fallback client
        if self.fallback_client:
            try:
                response = self.fallback_client.generate(prompt, temperature=0.1)
                return response
            except Exception as e:
                logger.error(f"Fallback client also failed: {e}")
                self.stats['failures'] += 1

        return None

    def _generate_metadata(self) -> Dict:
        """Generate metadata for review."""
        return {
            'generated_by': 'claude-sonnet-4-5-20250929-thinking',
            'generated_at': datetime.now().isoformat(),
            'prompt_version': 'v1.0',
            'confidence': 0.0  # Will be updated
        }

    def _create_failed_review(self) -> Dict:
        """Create a placeholder for failed review."""
        return {
            'vulnerability_analysis': {'summary': 'Failed to generate', 'severity': 'UNKNOWN'},
            'fix_analysis': {'summary': 'Failed to generate'},
            'code_review': {'security_improvements': []},
            'metadata': {'generated_by': 'error', 'confidence': 0.0}
        }

    def generate_all_reviews(
        self,
        benchmark_data: Dict[str, Any],
        limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generate reviews for all entries in benchmark with streaming output.

        Args:
            benchmark_data: Benchmark data dictionary
            limit: Maximum number of reviews to generate

        Returns:
            Benchmark data with added reviews
        """
        logger.info("Starting review generation with streaming output")
        logger.info(f"Parallel workers: {self.executor._max_workers}")
        start_time = time.time()

        checkpoint_freq = self.config.get('processing', {}).get('checkpoint_frequency', 50)

        # Create a list of all tasks
        tasks = []
        task_metadata = []  # (language, cwd, idx, entry)

        for language, cwd_dict in benchmark_data.items():
            for cwd, entries in cwd_dict.items():
                for idx, entry in enumerate(entries):
                    entry_id = f"{language}/{cwd}/{idx}"

                    if self.progress.is_completed(entry_id):
                        logger.debug(f"Skipping completed entry: {entry_id}")
                        continue

                    if limit and len(tasks) >= limit:
                        break

                    # Submit task to executor
                    future = self.executor.submit(
                        self.generate_review_for_entry,
                        entry, language, cwd, idx
                    )
                    tasks.append(future)
                    task_metadata.append((language, cwd, idx, entry, entry_id))

                if limit and len(tasks) >= limit:
                    break

            if limit and len(tasks) >= limit:
                break

        logger.info(f"Submitted {len(tasks)} tasks for processing")

        # Process completed tasks as they finish (streaming)
        processed = 0
        failed = 0

        for future in as_completed(tasks):
            # Find the corresponding metadata
            task_idx = tasks.index(future)
            language, cwd, idx, entry, entry_id = task_metadata[task_idx]

            try:
                review = future.result(timeout=300)  # 5 minute timeout per review
                entry['review'] = review

                self.progress.mark_completed(entry_id)
                processed += 1

                # Stream to disk immediately
                if self.streaming_output:
                    self._stream_write_entry(benchmark_data, language, cwd, idx)

                # Progress logging
                if processed % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    logger.info(f"Progress: {processed}/{len(tasks)} reviews completed ({rate:.1f} reviews/sec)")

                # Checkpoint
                if processed % checkpoint_freq == 0:
                    self.progress.save()
                    logger.info(f"Checkpoint: Saved progress at {processed} reviews")

            except Exception as e:
                logger.error(f"Error processing {entry_id}: {e}")
                self.stats['failures'] += 1
                failed += 1
                # Add a failed review placeholder
                entry['review'] = self._create_failed_review()

        # Final save
        self.progress.save()

        elapsed = time.time() - start_time
        logger.info(f"Completed {processed} reviews in {elapsed:.1f}s")
        logger.info(f"Success: {processed}, Failed: {failed}")
        logger.info(f"Average rate: {processed/elapsed:.2f} reviews/sec")
        logger.info(f"Stats: {self.stats}")

        return benchmark_data

    def _stream_write_entry(self, benchmark_data: Dict[str, Any], language: str, cwd: str, idx: int):
        """Write a single entry to disk immediately (streaming output).

        Args:
            benchmark_data: Full benchmark data
            language: Language key
            cwd: CWD key
            idx: Entry index
        """
        try:
            # Write the entire benchmark to disk (atomic update)
            # This ensures we always have a valid JSON file
            output_path = Path(self.output_file)
            temp_path = output_path.with_suffix('.tmp')

            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(benchmark_data, f, indent=2, ensure_ascii=False)

            # Atomic rename
            temp_path.replace(output_path)
            logger.debug(f"Streamed update for {language}/{cwd}/{idx}")

        except Exception as e:
            logger.warning(f"Failed to stream write entry: {e}")

    def generate_quality_report(self, benchmark_data: Dict) -> Dict:
        """Generate quality report for reviews.

        Args:
            benchmark_data: Benchmark data with reviews

        Returns:
            Quality report dictionary
        """
        total_reviews = 0
        confidence_scores = []
        severity_counts = defaultdict(int)
        fix_quality_counts = defaultdict(int)
        low_confidence_reviews = []

        for language, cwd_dict in benchmark_data.items():
            for cwd, entries in cwd_dict.items():
                for entry in entries:
                    if 'review' not in entry:
                        continue

                    total_reviews += 1
                    review = entry['review']

                    # Confidence
                    conf = review.get('metadata', {}).get('confidence', 0)
                    confidence_scores.append(conf)

                    if conf < 0.75:
                        low_confidence_reviews.append({
                            'id': f"{language}/{cwd}",
                            'confidence': conf,
                            'cwe': entry.get('CWE')
                        })

                    # Severity
                    severity = review.get('vulnerability_analysis', {}).get('severity', 'UNKNOWN')
                    severity_counts[severity] += 1

                    # Fix quality
                    fix_qual = review.get('fix_analysis', {}).get('fix_quality', 'UNKNOWN')
                    fix_quality_counts[fix_qual] += 1

        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0

        return {
            'total_reviews': total_reviews,
            'avg_confidence': round(avg_confidence, 3),
            'severity_distribution': dict(severity_counts),
            'fix_quality_distribution': dict(fix_quality_counts),
            'low_confidence_reviews': low_confidence_reviews,
            'stats': self.stats
        }
