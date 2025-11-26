"""Prompt formatting for review generation."""

import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


class PromptFormatter:
    """Format prompts for LLM review generation."""

    def __init__(self, prompt_templates_dir: str = "scripts/review_prompts"):
        """Initialize prompt formatter.

        Args:
            prompt_templates_dir: Directory containing prompt templates
        """
        self.templates_dir = Path(prompt_templates_dir)
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, str]:
        """Load all prompt templates.

        Returns:
            Dictionary mapping template names to template content
        """
        templates = {}

        template_files = {
            'vulnerability_analysis': 'vulnerability_analysis.txt',
            'fix_analysis': 'fix_analysis.txt',
            'code_review': 'code_review.txt'
        }

        for name, filename in template_files.items():
            template_path = self.templates_dir / filename
            if template_path.exists():
                with open(template_path, 'r', encoding='utf-8') as f:
                    templates[name] = f.read()
                    logger.debug(f"Loaded template: {name}")
            else:
                logger.warning(f"Template not found: {template_path}")
                templates[name] = ""

        return templates

    def format_vulnerability_analysis_prompt(
        self,
        entry: Dict[str, Any],
        cwe_info: Dict[str, str]
    ) -> str:
        """Format prompt for vulnerability analysis stage.

        Args:
            entry: Entry dictionary with code and metadata
            cwe_info: CWE information dictionary

        Returns:
            Formatted prompt string
        """
        template = self.templates.get('vulnerability_analysis', '')
        if not template:
            logger.error("Vulnerability analysis template not loaded")
            return ""

        # Extract vulnerable code
        vulnerable_code = self._extract_code(entry, 'vulnerable')
        if not vulnerable_code:
            logger.warning("No vulnerable code found in entry")
            vulnerable_code = "# Code not available"

        # Format the prompt
        prompt = template.format(
            cwe_id=entry.get('CWE', 'Unknown'),
            cwe_description=cwe_info.get('description', 'No description available'),
            cve_id=entry.get('CVE', 'N/A'),
            language=self._detect_language(entry),
            source=entry.get('source', 'unknown'),
            vulnerable_code=vulnerable_code
        )

        return prompt

    def format_fix_analysis_prompt(
        self,
        entry: Dict[str, Any],
        vulnerability_summary: str,
        severity: str
    ) -> str:
        """Format prompt for fix analysis stage.

        Args:
            entry: Entry dictionary with code and metadata
            vulnerability_summary: Summary from vulnerability analysis
            severity: Severity level from vulnerability analysis

        Returns:
            Formatted prompt string
        """
        template = self.templates.get('fix_analysis', '')
        if not template:
            logger.error("Fix analysis template not loaded")
            return ""

        # Extract codes
        vulnerable_code = self._extract_code(entry, 'vulnerable')
        fixed_code = self._extract_code(entry, 'benign')

        if not fixed_code:
            logger.warning("No fixed code found in entry")
            fixed_code = "# Fixed code not available"

        # Format the prompt
        prompt = template.format(
            vulnerability_summary=vulnerability_summary,
            severity=severity,
            language=self._detect_language(entry),
            vulnerable_code=vulnerable_code,
            fixed_code=fixed_code
        )

        return prompt

    def format_code_review_prompt(
        self,
        entry: Dict[str, Any],
        cwe_info: Dict[str, str],
        vulnerability_summary: str,
        fix_summary: str,
        severity: str,
        fix_quality: str,
        diff: str
    ) -> str:
        """Format prompt for code review stage.

        Args:
            entry: Entry dictionary
            cwe_info: CWE information
            vulnerability_summary: Summary from vulnerability analysis
            fix_summary: Summary from fix analysis
            severity: Severity level
            fix_quality: Fix quality assessment
            diff: Code diff string

        Returns:
            Formatted prompt string
        """
        template = self.templates.get('code_review', '')
        if not template:
            logger.error("Code review template not loaded")
            return ""

        # Format the prompt
        prompt = template.format(
            vulnerability_summary=vulnerability_summary,
            fix_summary=fix_summary,
            diff=diff,
            cwe_id=entry.get('CWE', 'Unknown'),
            cwe_description=cwe_info.get('description', 'No description available'),
            severity=severity,
            fix_quality=fix_quality
        )

        return prompt

    def _extract_code(self, entry: Dict[str, Any], code_type: str) -> str:
        """Extract code from entry.

        Args:
            entry: Entry dictionary
            code_type: 'vulnerable' or 'benign'

        Returns:
            Code string
        """
        # Try different field names based on entry structure
        if code_type == 'vulnerable':
            code_field_names = ['vulnerable_code', 'code_before', 'func_before']
        else:  # benign
            code_field_names = ['benign_code', 'code_after', 'func_after']

        # Try to find code in nested structure
        for field_name in code_field_names:
            if field_name in entry:
                code_data = entry[field_name]

                # Handle nested structure (e.g., {'context': code, 'func': code})
                if isinstance(code_data, dict):
                    # Priority: func > context
                    if 'func' in code_data and code_data['func']:
                        return code_data['func']
                    elif 'context' in code_data and code_data['context']:
                        return code_data['context']
                elif isinstance(code_data, str):
                    return code_data

        logger.warning(f"Could not find {code_type} code in entry")
        return ""

    def _detect_language(self, entry: Dict[str, Any]) -> str:
        """Detect programming language from entry.

        Args:
            entry: Entry dictionary

        Returns:
            Language name (e.g., 'c', 'python', 'java')
        """
        # Try to get language from entry metadata
        if 'language' in entry:
            return entry['language']

        # Try to infer from source
        source = entry.get('source', '').lower()
        if 'java' in source:
            return 'java'
        elif 'py' in source or 'python' in source:
            return 'python'

        # Default to C/C++ (most common in vulnerability datasets)
        return 'c'

    def truncate_code(self, code: str, max_lines: int = 100) -> str:
        """Truncate code to maximum lines.

        Args:
            code: Code string
            max_lines: Maximum number of lines

        Returns:
            Truncated code
        """
        if not code:
            return code

        lines = code.splitlines()
        if len(lines) <= max_lines:
            return code

        truncated = lines[:max_lines]
        truncated.append(f"... (truncated {len(lines) - max_lines} lines)")
        return '\n'.join(truncated)
