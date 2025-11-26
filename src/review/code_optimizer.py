"""Optimize code storage by extracting only the diff-relevant portions."""

import difflib
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class CodeOptimizer:
    """Extract and optimize code to show only relevant diff portions."""

    def __init__(self, context_lines: int = 5):
        """Initialize code optimizer.

        Args:
            context_lines: Number of context lines to keep around changes
        """
        self.context_lines = context_lines

    def optimize_code_pair(
        self,
        vulnerable_code: str,
        benign_code: str
    ) -> Dict[str, any]:
        """Optimize a pair of vulnerable/benign code by extracting only diff-relevant parts.

        Args:
            vulnerable_code: Original vulnerable code
            benign_code: Fixed benign code

        Returns:
            Dictionary with optimized code versions
        """
        if not vulnerable_code or not benign_code:
            return {
                'vulnerable_code': vulnerable_code,
                'benign_code': benign_code,
                'optimized': False,
                'reduction_ratio': 0.0
            }

        # Split into lines
        vuln_lines = vulnerable_code.strip().splitlines()
        benign_lines = benign_code.strip().splitlines()

        # Find changed line ranges
        changed_ranges = self._find_changed_ranges(vuln_lines, benign_lines)

        if not changed_ranges['vulnerable'] and not changed_ranges['benign']:
            # No changes detected, keep minimal version
            return {
                'vulnerable_code': vulnerable_code[:200] + '...' if len(vulnerable_code) > 200 else vulnerable_code,
                'benign_code': benign_code[:200] + '...' if len(benign_code) > 200 else benign_code,
                'optimized': True,
                'reduction_ratio': 0.9,
                'note': 'No significant changes detected'
            }

        # Extract context around changes
        vuln_optimized = self._extract_context(vuln_lines, changed_ranges['vulnerable'])
        benign_optimized = self._extract_context(benign_lines, changed_ranges['benign'])

        # Calculate reduction ratio
        original_size = len(vulnerable_code) + len(benign_code)
        optimized_size = len(vuln_optimized) + len(benign_optimized)
        reduction_ratio = 1.0 - (optimized_size / original_size) if original_size > 0 else 0.0

        return {
            'vulnerable_code': vuln_optimized,
            'benign_code': benign_optimized,
            'optimized': True,
            'reduction_ratio': reduction_ratio,
            'changed_line_count': len(changed_ranges['vulnerable']),
            'original_size': original_size,
            'optimized_size': optimized_size
        }

    def _find_changed_ranges(
        self,
        lines1: List[str],
        lines2: List[str]
    ) -> Dict[str, List[Tuple[int, int]]]:
        """Find ranges of lines that changed between two versions.

        Args:
            lines1: Lines from version 1
            lines2: Lines from version 2

        Returns:
            Dictionary with 'vulnerable' and 'benign' ranges
        """
        matcher = difflib.SequenceMatcher(None, lines1, lines2)

        vuln_ranges = []
        benign_ranges = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ('replace', 'delete', 'insert'):
                if i2 > i1:  # Lines in vulnerable version
                    vuln_ranges.append((i1, i2))
                if j2 > j1:  # Lines in benign version
                    benign_ranges.append((j1, j2))

        # Merge nearby ranges
        vuln_ranges = self._merge_nearby_ranges(vuln_ranges, lines1)
        benign_ranges = self._merge_nearby_ranges(benign_ranges, lines2)

        return {
            'vulnerable': vuln_ranges,
            'benign': benign_ranges
        }

    def _merge_nearby_ranges(
        self,
        ranges: List[Tuple[int, int]],
        lines: List[str],
        max_gap: int = 3
    ) -> List[Tuple[int, int]]:
        """Merge ranges that are close to each other.

        Args:
            ranges: List of (start, end) tuples
            lines: Source lines
            max_gap: Maximum gap between ranges to merge

        Returns:
            Merged ranges
        """
        if not ranges:
            return []

        # Sort by start position
        sorted_ranges = sorted(ranges)
        merged = [sorted_ranges[0]]

        for start, end in sorted_ranges[1:]:
            last_start, last_end = merged[-1]

            # If ranges are close, merge them
            if start - last_end <= max_gap:
                merged[-1] = (last_start, max(end, last_end))
            else:
                merged.append((start, end))

        return merged

    def _extract_context(
        self,
        lines: List[str],
        ranges: List[Tuple[int, int]]
    ) -> str:
        """Extract lines with context around specified ranges, ensuring correct line numbering and '...' markers.

        Args:
            lines: Source lines (list of strings).
            ranges: List of (start, end) tuples (0-indexed) indicating changed ranges.

        Returns:
            Extracted code with context and line numbers.
        """
        if not ranges:
            # If no changes, return the original code (or abbreviated if long)
            if len(lines) <= 2 * self.context_lines + 2: # heuristic for 'short' code
                return "\n".join([f"   {i+1:4d} | {line}" for i, line in enumerate(lines)])
            else:
                extracted_parts = []
                # Add beginning context
                for i in range(self.context_lines):
                    extracted_parts.append(f"   {i+1:4d} | {lines[i]}")
                extracted_parts.append('...')
                # Add ending context
                for i in range(len(lines) - self.context_lines, len(lines)):
                    extracted_parts.append(f"   {i+1:4d} | {lines[i]}")
                return "\n".join(extracted_parts)

        extracted_lines = []
        last_extracted_line_idx = -1

        # Sort ranges to ensure processing order and proper gap detection
        sorted_ranges = sorted(ranges)

        for start, end in sorted_ranges:
            context_start = max(0, start - self.context_lines)
            context_end = min(len(lines), end + self.context_lines)

            # If there's a gap between the current context start and the last extracted line
            if last_extracted_line_idx != -1 and context_start > last_extracted_line_idx:
                extracted_lines.append('...')

            # Adjust context_start if it overlaps with previous extraction
            current_extraction_start = max(context_start, last_extracted_line_idx)

            for i in range(current_extraction_start, context_end):
                if i >= len(lines): # Avoid index out of bounds
                    continue

                marker = '>>>' if start <= i < end else '   '
                extracted_lines.append(f"{marker} {i+1:4d} | {lines[i]}")

            last_extracted_line_idx = context_end

        # Ensure no trailing '...' if the last extracted line is the end of the file
        if last_extracted_line_idx < len(lines) and (not extracted_lines or extracted_lines[-1] != '...'):
             # This means there's unextracted content at the end of the file
             # but we only add '...' if there's an actual gap (which the loop would handle)
             # or if the entire file was not extracted and the end part is missing
             # For now, let's keep it simple and rely on the loop's '...' placement
             pass

        return "\n".join(extracted_lines)

    def optimize_entry(self, entry: Dict) -> Dict:
        """Optimize code in a benchmark entry.

        Args:
            entry: Benchmark entry with vulnerable_code and benign_code

        Returns:
            Optimized entry
        """
        # Extract code from nested structure
        vuln_code = self._extract_code_from_field(entry.get('vulnerable_code', ''))
        benign_code = self._extract_code_from_field(entry.get('benign_code', ''))

        # Optimize
        result = self.optimize_code_pair(vuln_code, benign_code)

        # Update entry
        if result['optimized']:
            # Update with optimized versions
            if isinstance(entry.get('vulnerable_code'), dict):
                entry['vulnerable_code']['context'] = result['vulnerable_code']
                entry['vulnerable_code']['_original_size'] = result.get('original_size', 0)
            else:
                entry['vulnerable_code'] = result['vulnerable_code']

            if isinstance(entry.get('benign_code'), dict):
                entry['benign_code']['context'] = result['benign_code']
                entry['benign_code']['_original_size'] = result.get('original_size', 0)
            else:
                entry['benign_code'] = result['benign_code']

            # Add optimization metadata
            entry['_optimization'] = {
                'enabled': True,
                'reduction_ratio': result['reduction_ratio'],
                'original_size': result['original_size'],
                'optimized_size': result['optimized_size']
            }

            logger.debug(f"Optimized code by {result['reduction_ratio']*100:.1f}%")

        return entry

    def _extract_code_from_field(self, code_field) -> str:
        """Extract code string from field (handles both string and dict).

        Args:
            code_field: Code field (string or dict)

        Returns:
            Code string
        """
        if isinstance(code_field, dict):
            # Try different keys
            for key in ['context', 'func', 'code']:
                if key in code_field and code_field[key]:
                    return str(code_field[key])
            return ''
        elif isinstance(code_field, str):
            return code_field
        else:
            return ''

    def create_unified_diff_view(
        self,
        vulnerable_code: str,
        benign_code: str,
        filename_before: str = 'vulnerable',
        filename_after: str = 'benign'
    ) -> str:
        """Create a compact unified diff view.

        Args:
            vulnerable_code: Original code
            benign_code: Fixed code
            filename_before: Label for before
            filename_after: Label for after

        Returns:
            Unified diff string
        """
        vuln_lines = vulnerable_code.splitlines(keepends=True)
        benign_lines = benign_code.splitlines(keepends=True)

        diff = difflib.unified_diff(
            vuln_lines,
            benign_lines,
            fromfile=filename_before,
            tofile=filename_after,
            lineterm='',
            n=self.context_lines
        )

        return ''.join(diff)

    def get_optimization_stats(self, benchmark_data: Dict) -> Dict:
        """Get statistics about code optimization.

        Args:
            benchmark_data: Full benchmark data

        Returns:
            Optimization statistics
        """
        total_entries = 0
        optimized_entries = 0
        total_original_size = 0
        total_optimized_size = 0

        for language, cwd_dict in benchmark_data.items():
            for cwd, entries in cwd_dict.items():
                for entry in entries:
                    total_entries += 1

                    if '_optimization' in entry and entry['_optimization'].get('enabled'):
                        optimized_entries += 1
                        total_original_size += entry['_optimization'].get('original_size', 0)
                        total_optimized_size += entry['_optimization'].get('optimized_size', 0)

        overall_reduction = 1.0 - (total_optimized_size / total_original_size) if total_original_size > 0 else 0.0

        return {
            'total_entries': total_entries,
            'optimized_entries': optimized_entries,
            'optimization_rate': optimized_entries / total_entries if total_entries > 0 else 0.0,
            'total_original_size': total_original_size,
            'total_optimized_size': total_optimized_size,
            'overall_reduction_ratio': overall_reduction,
            'estimated_token_savings': int((total_original_size - total_optimized_size) / 4)  # ~4 chars per token
        }
