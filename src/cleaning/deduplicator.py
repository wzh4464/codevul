"""Deduplication cleaning step - placeholder."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

from .base import CleaningResult, CleaningStep

logger = logging.getLogger(__name__)


class Deduplicator(CleaningStep):
    """Remove duplicate entries (placeholder for now)."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.method = self.config.get('method', 'signature')
        self.cross_dataset = self.config.get('cross_dataset', True)

    def process(
        self,
        input_path: Path,
        output_path: Path,
        cache_dir: Optional[Path] = None
    ) -> CleaningResult:
        """
        Deduplication step (currently passes through).

        TODO: Implement signature-based deduplication
        """
        # For now, pass through all rows
        import shutil
        shutil.copy2(input_path, output_path)

        # Count rows
        import csv
        count = 0
        with open(input_path, 'r') as f:
            count = sum(1 for _ in csv.DictReader(f))

        logger.info(f"{self.name}: pass-through mode, {count} rows")

        return CleaningResult(
            step_name=self.name,
            input_count=count,
            output_count=count,
            filtered_count=0,
            success=True,
            metadata={'mode': 'pass-through'}
        )
