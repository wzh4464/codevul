"""Code validation cleaning step."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, Optional

from .base import CleaningResult, CleaningStep

logger = logging.getLogger(__name__)


class CodeValidator(CleaningStep):
    """Validate code fields."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.skip_empty = self.config.get('skip_empty', True)
        self.skip_identical = self.config.get('skip_identical', True)
        self.min_length = self.config.get('min_code_length', 10)

    def validate_row(self, row: Dict[str, str]) -> bool:
        """Validate code before and after fields."""
        code_before = row.get('code_before', '').strip()
        code_after = row.get('code_after', '').strip()

        # Check for empty code
        if self.skip_empty:
            if not code_before or not code_after:
                return False

        # Check minimum length
        if len(code_before) < self.min_length or len(code_after) < self.min_length:
            return False

        # Check for identical code
        if self.skip_identical:
            if code_before == code_after:
                return False

        return True

    def process(
        self,
        input_path: Path,
        output_path: Path,
        cache_dir: Optional[Path] = None
    ) -> CleaningResult:
        """Process CSV file with code validation."""
        input_count = 0
        output_count = 0

        try:
            with open(input_path, 'r', encoding='utf-8') as infile, \
                 open(output_path, 'w', encoding='utf-8', newline='') as outfile:

                reader = csv.DictReader(infile)
                writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
                writer.writeheader()

                for row in reader:
                    input_count += 1
                    if self.validate_row(row):
                        writer.writerow(row)
                        output_count += 1

            filtered_count = input_count - output_count
            pct = (filtered_count/input_count*100) if input_count > 0 else 0
            logger.info(
                f"{self.name}: {input_count} → {output_count} "
                f"(filtered {filtered_count}, {pct:.1f}%)"
            )

            return CleaningResult(
                step_name=self.name,
                input_count=input_count,
                output_count=output_count,
                filtered_count=filtered_count,
                success=True
            )

        except Exception as e:
            logger.error(f"{self.name} failed: {e}", exc_info=True)
            return CleaningResult(
                step_name=self.name,
                input_count=input_count,
                output_count=output_count,
                filtered_count=0,
                success=False,
                error=str(e)
            )
