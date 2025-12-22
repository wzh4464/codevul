"""CWE validation cleaning step."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, Optional

from .base import CleaningResult, CleaningStep
from ..utils.cwe_utils import normalize_cwe, is_unknown_cwe

logger = logging.getLogger(__name__)


class CWEValidator(CleaningStep):
    """Validate and normalize CWE fields."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.reject_unknown = self.config.get('reject_unknown', True)
        self.reject_invalid = self.config.get('reject_invalid', True)

    def validate_row(self, row: Dict[str, str]) -> bool:
        """Check if CWE is valid."""
        cwe = row.get('cwe', '').strip()

        if not cwe:
            return not self.reject_invalid

        # Split multiple CWEs
        cwes = [c.strip() for c in cwe.split('|') if c.strip()]
        if not cwes:
            return not self.reject_invalid

        # Check for unknown CWEs
        for c in cwes:
            normalized = normalize_cwe(c)
            if not normalized:
                if self.reject_invalid:
                    return False
            elif is_unknown_cwe(normalized):
                if self.reject_unknown:
                    return False

        return True

    def transform_row(self, row: Dict[str, str]) -> Dict[str, str]:
        """Normalize CWE format."""
        cwe = row.get('cwe', '').strip()
        if cwe:
            # Split, normalize, and rejoin
            cwes = [c.strip() for c in cwe.split('|') if c.strip()]
            normalized = [normalize_cwe(c) for c in cwes]
            normalized = [c for c in normalized if c and not is_unknown_cwe(c)]
            row['cwe'] = '|'.join(normalized)
        return row

    def process(
        self,
        input_path: Path,
        output_path: Path,
        cache_dir: Optional[Path] = None
    ) -> CleaningResult:
        """Process CSV file with CWE validation."""
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
                        row = self.transform_row(row)
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
