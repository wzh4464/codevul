"""Command-line interface for CodeVul Benchmark Pipeline."""

import argparse
import logging
import sys
from pathlib import Path

from .pipeline.orchestrator import PipelineConfig, PipelineOrchestrator
from .pipeline import normalize, clean, sample


def setup_logging(level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def cmd_normalize(args):
    """Run normalization step."""
    config = PipelineConfig.from_yaml(args.config)

    if args.dataset:
        config.dataset_names = [args.dataset]

    if args.limit:
        config.limit = args.limit

    orchestrator = PipelineOrchestrator(config)
    results = orchestrator.run_normalize_step()

    # Print summary
    successful = sum(1 for r in results.values() if r.success)
    print(f"\n✓ Normalization complete: {successful}/{len(results)} successful")

    return 0 if successful > 0 else 1


def cmd_clean(args):
    """Run cleaning step."""
    config = PipelineConfig.from_yaml(args.config)
    orchestrator = PipelineOrchestrator(config)
    results = orchestrator.run_clean_step()

    # Print summary
    successful = sum(1 for r in results.values() if r.success)
    print(f"\n✓ Cleaning complete: {successful}/{len(results)} successful")

    return 0 if successful > 0 else 1


def cmd_transform(args):
    """Run transformation step."""
    config = PipelineConfig.from_yaml(args.config)
    orchestrator = PipelineOrchestrator(config)
    result = orchestrator.run_transform_step()

    if result and result.success:
        print(f"\n✓ Transform complete: {result.total_entries} entries, {result.total_cwds} CWDs")
        return 0
    else:
        print(f"\n✗ Transform failed: {result.error if result else 'Unknown error'}")
        return 1


def cmd_sample(args):
    """Run sample generation step."""
    config = PipelineConfig.from_yaml(args.config)
    orchestrator = PipelineOrchestrator(config)
    results = orchestrator.run_sample_step()

    print(f"\n✓ Sample generation complete: {len(results)} samples generated")

    return 0 if results else 1


def cmd_pipeline(args):
    """Run full pipeline."""
    config = PipelineConfig.from_yaml(args.config)

    if args.limit:
        config.limit = args.limit

    orchestrator = PipelineOrchestrator(config)
    result = orchestrator.run_full_pipeline()

    if result.success:
        print(f"\n✓ Pipeline complete in {result.duration:.1f}s")
        return 0
    else:
        print(f"\n✗ Pipeline failed: {result.error}")
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CodeVul Benchmark Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s normalize                # Normalize all datasets
  %(prog)s normalize --dataset msr  # Normalize specific dataset
  %(prog)s clean                    # Clean normalized data
  %(prog)s pipeline                 # Run full pipeline
  %(prog)s sample                   # Generate samples
        """
    )

    parser.add_argument(
        '--config',
        default='config/pipeline.yaml',
        help='Path to configuration file'
    )

    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Normalize command
    parser_normalize = subparsers.add_parser('normalize', help='Normalize datasets')
    parser_normalize.add_argument('--dataset', help='Specific dataset to normalize')
    parser_normalize.add_argument('--limit', type=int, help='Limit rows per dataset')
    parser_normalize.set_defaults(func=cmd_normalize)

    # Clean command
    parser_clean = subparsers.add_parser('clean', help='Clean normalized data')
    parser_clean.set_defaults(func=cmd_clean)

    # Transform command
    parser_transform = subparsers.add_parser('transform', help='Transform to benchmark')
    parser_transform.set_defaults(func=cmd_transform)

    # Sample command
    parser_sample = subparsers.add_parser('sample', help='Generate samples')
    parser_sample.set_defaults(func=cmd_sample)

    # Pipeline command
    parser_pipeline = subparsers.add_parser('pipeline', help='Run full pipeline')
    parser_pipeline.add_argument('--limit', type=int, help='Limit rows per dataset')
    parser_pipeline.set_defaults(func=cmd_pipeline)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Setup logging
    setup_logging(args.log_level)

    # Run command
    try:
        return args.func(args)
    except Exception as e:
        logging.error(f"Command failed: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
