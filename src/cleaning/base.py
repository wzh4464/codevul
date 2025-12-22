"""Base classes for cleaning steps."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CleaningResult:
    """Result of a cleaning step."""

    step_name: str
    input_count: int
    output_count: int
    filtered_count: int
    success: bool
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def filtered_percentage(self) -> float:
        """Calculate percentage of rows filtered."""
        if self.input_count == 0:
            return 0.0
        return (self.filtered_count / self.input_count) * 100


class CleaningStep(ABC):
    """Base class for all cleaning steps."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize cleaning step.

        Args:
            config: Configuration dictionary for this step
        """
        self.config = config or {}
        self.name = self.__class__.__name__

    @abstractmethod
    def process(
        self,
        input_path: Path,
        output_path: Path,
        cache_dir: Optional[Path] = None
    ) -> CleaningResult:
        """
        Process the input CSV and write cleaned output.

        Args:
            input_path: Path to input CSV file
            output_path: Path to write cleaned CSV
            cache_dir: Optional cache directory

        Returns:
            CleaningResult with statistics
        """
        pass

    def validate_row(self, row: Dict[str, str]) -> bool:
        """
        Validate a single row. Override in subclasses.

        Args:
            row: Dictionary with keys: cwe, code_before, code_after, commit_url, language

        Returns:
            True if row should be kept, False to filter it
        """
        return True

    def transform_row(self, row: Dict[str, str]) -> Dict[str, str]:
        """
        Transform a row. Override in subclasses.

        Args:
            row: Input row dictionary

        Returns:
            Transformed row dictionary
        """
        return row

    def __str__(self) -> str:
        return f"{self.name}"

    def __repr__(self) -> str:
        return f"{self.name}(config={self.config})"
