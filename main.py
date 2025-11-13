"""Main entry point for benchmark transformation."""

import sys
from pathlib import Path

# Add the scripts directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import and run the transform_benchmark main function
from scripts.transform_benchmark import main as transform_main


def main() -> None:
    """Run the benchmark transformation pipeline."""
    transform_main()


if __name__ == "__main__":
    main()
