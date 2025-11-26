#!/usr/bin/env python3
"""Generate AI-based review comments for vulnerability dataset.

Usage:
    python scripts/generate_reviews.py --input benchmark_transformed.json --output benchmark_with_reviews.json
    python scripts/generate_reviews.py --resume --limit 100
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from review.generator import ReviewGenerator


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('review_generation.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def load_benchmark(input_path: Path) -> dict:
    """Load benchmark data from JSON file.

    Args:
        input_path: Path to input JSON file

    Returns:
        Benchmark data dictionary
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Loading benchmark from {input_path}")

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logger.info(f"Loaded {sum(len(entries) for cwd_dict in data.values() for entries in cwd_dict.values())} entries")
        return data
    except Exception as e:
        logger.error(f"Failed to load benchmark: {e}")
        sys.exit(1)


def save_benchmark(data: dict, output_path: Path, pretty: bool = True):
    """Save benchmark data to JSON file.

    Args:
        data: Benchmark data dictionary
        output_path: Path to output JSON file
        pretty: Whether to pretty-print JSON
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Saving benchmark to {output_path}")

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)
        logger.info(f"Saved successfully")
    except Exception as e:
        logger.error(f"Failed to save benchmark: {e}")
        sys.exit(1)


def save_quality_report(report: dict, output_path: Path):
    """Save quality report.

    Args:
        report: Quality report dictionary
        output_path: Path to output file
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Saving quality report to {output_path}")

    try:
        # Generate markdown report
        lines = [
            "# Review Quality Report\n",
            f"## Summary\n",
            f"- **Total Reviews**: {report['total_reviews']}",
            f"- **Average Confidence**: {report['avg_confidence']:.3f}",
            f"- **Low Confidence Reviews**: {len(report['low_confidence_reviews'])} ({len(report['low_confidence_reviews'])/report['total_reviews']*100:.1f}%)" if report['total_reviews'] > 0 else "- **Low Confidence Reviews**: 0",
            f"\n## Severity Distribution\n"
        ]

        for severity, count in sorted(report['severity_distribution'].items()):
            lines.append(f"- **{severity}**: {count}")

        lines.append(f"\n## Fix Quality Distribution\n")
        for quality, count in sorted(report['fix_quality_distribution'].items()):
            lines.append(f"- **{quality}**: {count}")

        lines.append(f"\n## Statistics\n")
        for key, value in report['stats'].items():
            if not key.startswith('regen_'):
                lines.append(f"- **{key}**: {value}")

        if report['low_confidence_reviews']:
            lines.append(f"\n## Low Confidence Reviews\n")
            lines.append("| ID | CWE | Confidence |")
            lines.append("|-----|-----|------------|")
            for item in report['low_confidence_reviews'][:20]:  # First 20
                lines.append(f"| {item['id']} | {item['cwe']} | {item['confidence']:.3f} |")

            if len(report['low_confidence_reviews']) > 20:
                lines.append(f"\n... and {len(report['low_confidence_reviews']) - 20} more")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        logger.info("Quality report saved")
    except Exception as e:
        logger.error(f"Failed to save quality report: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate AI-based review comments for vulnerability dataset'
    )
    parser.add_argument(
        '--input',
        type=Path,
        default=Path('benchmark_transformed.json'),
        help='Input benchmark JSON file (default: benchmark_transformed.json)'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('benchmark_with_reviews.json'),
        help='Output benchmark JSON file with reviews (default: benchmark_with_reviews.json)'
    )
    parser.add_argument(
        '--config',
        type=Path,
        default=Path('config/review_config.yaml'),
        help='Configuration file (default: config/review_config.yaml)'
    )
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume from previous run'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of reviews to generate (for testing)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--report',
        type=Path,
        default=Path('review_quality_report.md'),
        help='Quality report output file (default: review_quality_report.md)'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("="*80)
    logger.info("Review Comment Generation")
    logger.info("="*80)

    # Check if input exists
    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        logger.info("Please run scripts/transform_benchmark.py first to generate benchmark_transformed.json")
        sys.exit(1)

    # Check if config exists
    if not args.config.exists():
        logger.error(f"Config file not found: {args.config}")
        logger.info("Please ensure config/review_config.yaml exists")
        sys.exit(1)

    # Load benchmark
    benchmark_data = load_benchmark(args.input)

    # Initialize generator
    logger.info("Initializing ReviewGenerator...")
    try:
        generator = ReviewGenerator(config_path=str(args.config), resume=args.resume)
        # Configure output file
        generator.output_file = str(args.output)
    except Exception as e:
        logger.error(f"Failed to initialize generator: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Generate reviews
    logger.info("Generating reviews with streaming output...")
    logger.info(f"Output will be written to: {args.output}")
    logger.info(f"Concurrent workers: 16")
    try:
        benchmark_with_reviews = generator.generate_all_reviews(benchmark_data, limit=args.limit)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        logger.info("Progress has been saved. Use --resume to continue.")
        logger.info(f"Partial results available in: {args.output}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed during generation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Save output
    save_benchmark(benchmark_with_reviews, args.output)

    # Generate quality report
    logger.info("Generating quality report...")
    quality_report = generator.generate_quality_report(benchmark_with_reviews)
    save_quality_report(quality_report, args.report)

    logger.info("="*80)
    logger.info("Review generation completed!")
    logger.info(f"Output: {args.output}")
    logger.info(f"Report: {args.report}")
    logger.info("="*80)


if __name__ == '__main__':
    main()
