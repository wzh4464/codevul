"""Language filtering cleaning step."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, Optional

from .base import CleaningResult, CleaningStep

logger = logging.getLogger(__name__)

LANGUAGE_MAPPING = {
    'c': 'c/c++',
    'C': 'c/c++',
    'cpp': 'c/c++',
    'c++': 'c/c++',
    'C++': 'c/c++',
    'Cpp': 'c/c++',
    'CPP': 'c/c++',
    'C/C++': 'c/c++',
    'java': 'java',
    'Java': 'java',
    'JAVA': 'java',
}


class LanguageFilter(CleaningStep):
    """Filter and normalize language field."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.allowed = set(self.config.get('allowed', ['c', 'c++', 'java']))
        self.mapping = self.config.get('normalize_mapping', LANGUAGE_MAPPING)

    def validate_row(self, row: Dict[str, str]) -> bool:
        """Check if language is allowed."""
        language = row.get('language', '').strip()
        normalized = self.mapping.get(language, language)
        return normalized in self.allowed

    def transform_row(self, row: Dict[str, str]) -> Dict[str, str]:
        """Normalize language field."""
        language = row.get('language', '').strip()
        row['language'] = self.mapping.get(language, language)
        return row

    def process(
        self,
        input_path: Path,
        output_path: Path,
        cache_dir: Optional[Path] = None
    ) -> CleaningResult:
        """Process CSV file with language filtering."""
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
