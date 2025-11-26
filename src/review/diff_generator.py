"""Generate unified diff between vulnerable and fixed code."""

import difflib
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class DiffGenerator:
    """Generate code diffs for review analysis."""

    def __init__(self, context_lines: int = 3):
        """Initialize diff generator.

        Args:
            context_lines: Number of context lines around changes
        """
        self.context_lines = context_lines

    def generate_unified_diff(
        self,
        code_before: str,
        code_after: str,
        filename_before: str = "vulnerable.c",
        filename_after: str = "fixed.c"
    ) -> str:
        """Generate a unified diff between two code versions.

        Args:
            code_before: Original vulnerable code
            code_after: Fixed code
            filename_before: Label for vulnerable version
            filename_after: Label for fixed version

        Returns:
            Unified diff string
        """
        if not code_before or not code_after:
            logger.warning("Empty code provided for diff generation")
            return ""

        # Split into lines
        lines_before = code_before.splitlines(keepends=True)
        lines_after = code_after.splitlines(keepends=True)

        # Generate unified diff
        diff_lines = difflib.unified_diff(
            lines_before,
            lines_after,
            fromfile=filename_before,
            tofile=filename_after,
            lineterm='',
            n=self.context_lines
        )

        # Join and return
        diff_text = '\n'.join(diff_lines)

        if not diff_text:
            logger.debug("No differences found between code versions")
            return "No changes detected"

        return diff_text

    def generate_side_by_side(
        self,
        code_before: str,
        code_after: str,
        width: int = 80
    ) -> str:
        """Generate a side-by-side comparison.

        Args:
            code_before: Original vulnerable code
            code_after: Fixed code
            width: Maximum width for each column

        Returns:
            Side-by-side diff string
        """
        lines_before = code_before.splitlines()
        lines_after = code_after.splitlines()

        # Use HtmlDiff for side-by-side but convert to text
        diff = difflib.HtmlDiff()
        html_diff = diff.make_table(
            lines_before,
            lines_after,
            "Vulnerable",
            "Fixed",
            context=True,
            numlines=self.context_lines
        )

        # For now, just return unified diff (side-by-side is complex in text)
        return self.generate_unified_diff(code_before, code_after)

    def get_changed_lines(
        self,
        code_before: str,
        code_after: str
    ) -> dict:
        """Identify which lines were changed, added, or removed.

        Args:
            code_before: Original vulnerable code
            code_after: Fixed code

        Returns:
            Dictionary with added_lines, removed_lines, changed_lines
        """
        lines_before = code_before.splitlines()
        lines_after = code_after.splitlines()

        # Use SequenceMatcher to find differences
        matcher = difflib.SequenceMatcher(None, lines_before, lines_after)

        added_lines = []
        removed_lines = []
        changed_regions = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'delete':
                removed_lines.extend(range(i1 + 1, i2 + 1))  # 1-indexed
            elif tag == 'insert':
                added_lines.extend(range(j1 + 1, j2 + 1))
            elif tag == 'replace':
                removed_lines.extend(range(i1 + 1, i2 + 1))
                added_lines.extend(range(j1 + 1, j2 + 1))
                changed_regions.append({
                    'before': (i1 + 1, i2 + 1),
                    'after': (j1 + 1, j2 + 1)
                })

        return {
            'added_lines': added_lines,
            'removed_lines': removed_lines,
            'changed_regions': changed_regions
        }

    def get_vulnerability_affected_lines(
        self,
        code_before: str,
        code_after: str,
        max_lines: int = 10
    ) -> List[int]:
        """Get the line numbers in vulnerable code that were changed.

        This is useful for identifying which lines in the vulnerable code
        contain the security issues.

        Args:
            code_before: Original vulnerable code
            code_after: Fixed code
            max_lines: Maximum number of lines to return

        Returns:
            List of 1-indexed line numbers in vulnerable code
        """
        changes = self.get_changed_lines(code_before, code_after)

        # Combine removed and changed lines (these are the vulnerable lines)
        vulnerable_lines = sorted(set(changes['removed_lines']))

        # Limit to max_lines
        if len(vulnerable_lines) > max_lines:
            logger.debug(f"Truncating {len(vulnerable_lines)} affected lines to {max_lines}")
            vulnerable_lines = vulnerable_lines[:max_lines]

        return vulnerable_lines

    def generate_compact_diff(
        self,
        code_before: str,
        code_after: str,
        max_lines: int = 50
    ) -> str:
        """Generate a compact diff with limited context.

        Useful for LLM prompts with token limits.

        Args:
            code_before: Original vulnerable code
            code_after: Fixed code
            max_lines: Maximum lines in output

        Returns:
            Compact diff string
        """
        # Generate full diff
        full_diff = self.generate_unified_diff(code_before, code_after)

        # Split into lines
        diff_lines = full_diff.splitlines()

        if len(diff_lines) <= max_lines:
            return full_diff

        # Keep header and truncate body
        header_lines = [line for line in diff_lines[:5] if line.startswith('---') or line.startswith('+++') or line.startswith('@@')]
        body_lines = diff_lines[5:]

        # Keep first max_lines - len(header) - 1 lines of body
        remaining = max_lines - len(header_lines) - 1
        truncated_body = body_lines[:remaining]

        result = header_lines + truncated_body + [f"... (truncated {len(body_lines) - remaining} lines)"]

        return '\n'.join(result)
