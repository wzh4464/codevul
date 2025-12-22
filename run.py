#!/usr/bin/env python3
"""CodeVul Benchmark Pipeline - Main Entry Point."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
