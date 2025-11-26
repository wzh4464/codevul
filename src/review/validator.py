"""Validation and confidence scoring for generated reviews."""

import json
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ReviewValidator:
    """Validate and score review comment quality."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize validator.

        Args:
            config: Configuration dictionary with validation settings
        """
        self.config = config
        self.validation_config = config.get('validation', {})
        self.required_fields = self.validation_config.get('required_fields', {})
        self.allowed_values = self.validation_config.get('allowed_values', {})
        self.confidence_weights = self.validation_config.get('confidence_weights', {})

    def validate_json_structure(self, data: Any, expected_fields: List[str]) -> tuple[bool, List[str]]:
        """Validate that JSON has required fields.

        Args:
            data: Parsed JSON data
            expected_fields: List of required field names

        Returns:
            Tuple of (is_valid, list_of_missing_fields)
        """
        if not isinstance(data, dict):
            return False, expected_fields

        missing_fields = [field for field in expected_fields if field not in data]
        return len(missing_fields) == 0, missing_fields

    def validate_vulnerability_analysis(self, analysis: Dict) -> tuple[bool, List[str]]:
        """Validate vulnerability analysis section.

        Args:
            analysis: Vulnerability analysis dictionary

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        required = self.required_fields.get('vulnerability_analysis', [])
        is_valid, missing = self.validate_json_structure(analysis, required)

        issues = []
        if not is_valid:
            issues.append(f"Missing fields: {', '.join(missing)}")

        # Validate severity
        if 'severity' in analysis:
            allowed_severities = self.allowed_values.get('severity', [])
            if allowed_severities and analysis['severity'] not in allowed_severities:
                issues.append(f"Invalid severity: {analysis['severity']}")

        # Validate affected_lines is a list
        if 'affected_lines' in analysis:
            if not isinstance(analysis['affected_lines'], list):
                issues.append("affected_lines must be a list")

        return len(issues) == 0, issues

    def validate_fix_analysis(self, analysis: Dict) -> tuple[bool, List[str]]:
        """Validate fix analysis section.

        Args:
            analysis: Fix analysis dictionary

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        required = self.required_fields.get('fix_analysis', [])
        is_valid, missing = self.validate_json_structure(analysis, required)

        issues = []
        if not is_valid:
            issues.append(f"Missing fields: {', '.join(missing)}")

        # Validate fix_quality
        if 'fix_quality' in analysis:
            allowed_qualities = self.allowed_values.get('fix_quality', [])
            if allowed_qualities and analysis['fix_quality'] not in allowed_qualities:
                issues.append(f"Invalid fix_quality: {analysis['fix_quality']}")

        # Validate completeness
        if 'completeness' in analysis:
            allowed_completeness = self.allowed_values.get('completeness', [])
            if allowed_completeness and analysis['completeness'] not in allowed_completeness:
                issues.append(f"Invalid completeness: {analysis['completeness']}")

        # Validate changes_made is a list
        if 'changes_made' in analysis:
            if not isinstance(analysis['changes_made'], list):
                issues.append("changes_made must be a list")

        return len(issues) == 0, issues

    def validate_code_review(self, review: Dict) -> tuple[bool, List[str]]:
        """Validate code review section.

        Args:
            review: Code review dictionary

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        required = self.required_fields.get('code_review', [])
        is_valid, missing = self.validate_json_structure(review, required)

        issues = []
        if not is_valid:
            issues.append(f"Missing fields: {', '.join(missing)}")

        # Validate that lists are actually lists
        for list_field in ['security_improvements', 'remaining_concerns', 'best_practices']:
            if list_field in review and not isinstance(review[list_field], list):
                issues.append(f"{list_field} must be a list")

        return len(issues) == 0, issues

    def validate_review(self, review: Dict) -> tuple[bool, Dict[str, List[str]]]:
        """Validate complete review structure.

        Args:
            review: Complete review dictionary

        Returns:
            Tuple of (is_valid, dict_of_issues_by_section)
        """
        all_issues = {}

        # Validate vulnerability analysis
        if 'vulnerability_analysis' in review:
            valid, issues = self.validate_vulnerability_analysis(review['vulnerability_analysis'])
            if issues:
                all_issues['vulnerability_analysis'] = issues
        else:
            all_issues['vulnerability_analysis'] = ["Section missing"]

        # Validate fix analysis
        if 'fix_analysis' in review:
            valid, issues = self.validate_fix_analysis(review['fix_analysis'])
            if issues:
                all_issues['fix_analysis'] = issues
        else:
            all_issues['fix_analysis'] = ["Section missing"]

        # Validate code review
        if 'code_review' in review:
            valid, issues = self.validate_code_review(review['code_review'])
            if issues:
                all_issues['code_review'] = issues
        else:
            all_issues['code_review'] = ["Section missing"]

        return len(all_issues) == 0, all_issues

    def calculate_confidence(self, review: Dict, entry: Dict) -> float:
        """Calculate confidence score for a review.

        Args:
            review: Generated review dictionary
            entry: Original entry being reviewed

        Returns:
            Confidence score between 0 and 1
        """
        scores = {}

        # Weight: JSON validity (0.25)
        is_valid, issues = self.validate_review(review)
        scores['json_valid'] = 1.0 if is_valid else 0.0

        # Weight: All fields present (0.20)
        all_sections = ['vulnerability_analysis', 'fix_analysis', 'code_review']
        present_sections = sum(1 for section in all_sections if section in review)
        scores['all_fields_present'] = present_sections / len(all_sections)

        # Weight: CWE mentioned (0.15)
        cwe_id = entry.get('CWE', '')
        review_text = json.dumps(review).lower()
        scores['cwe_mentioned'] = 1.0 if cwe_id.lower() in review_text else 0.0

        # Weight: Line numbers valid (0.10)
        if 'vulnerability_analysis' in review:
            affected_lines = review['vulnerability_analysis'].get('affected_lines', [])
            if isinstance(affected_lines, list) and len(affected_lines) > 0:
                scores['line_numbers_valid'] = 1.0
            else:
                scores['line_numbers_valid'] = 0.5  # Partial credit
        else:
            scores['line_numbers_valid'] = 0.0

        # Weight: Reasonable length (0.10)
        text_length = len(json.dumps(review))
        if 500 < text_length < 5000:  # Reasonable range
            scores['reasonable_length'] = 1.0
        elif text_length < 200:  # Too short
            scores['reasonable_length'] = 0.3
        elif text_length > 10000:  # Too long
            scores['reasonable_length'] = 0.7
        else:
            scores['reasonable_length'] = 0.8

        # Weight: No generic response (0.10)
        generic_phrases = [
            'as an ai', 'i cannot', 'i apologize',
            'sorry', 'unable to', 'i do not have'
        ]
        has_generic = any(phrase in review_text for phrase in generic_phrases)
        scores['no_generic_response'] = 0.0 if has_generic else 1.0

        # Weight: Severity appropriate (0.10)
        if 'vulnerability_analysis' in review:
            severity = review['vulnerability_analysis'].get('severity', '')
            # Check if severity makes sense (not empty, is uppercase)
            scores['severity_appropriate'] = 1.0 if severity and severity.isupper() else 0.5
        else:
            scores['severity_appropriate'] = 0.0

        # Calculate weighted confidence
        confidence = 0.0
        for key, weight in self.confidence_weights.items():
            score = scores.get(key, 0.0)
            confidence += score * weight
            logger.debug(f"{key}: {score:.2f} (weight: {weight:.2f})")

        logger.debug(f"Overall confidence: {confidence:.2f}")
        return round(confidence, 3)

    def parse_json_response(self, response: str) -> Optional[Dict]:
        """Parse JSON from LLM response, handling various formats.

        Args:
            response: Raw LLM response

        Returns:
            Parsed JSON dictionary or None
        """
        # Strategy 1: Direct parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract from markdown code block
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Strategy 3: Find first complete JSON object
        brace_count = 0
        start_idx = response.find('{')
        if start_idx == -1:
            return None

        for i in range(start_idx, len(response)):
            if response[i] == '{':
                brace_count += 1
            elif response[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    try:
                        return json.loads(response[start_idx:i+1])
                    except json.JSONDecodeError:
                        pass
                    break

        logger.warning("Failed to parse JSON from response")
        return None

    def should_regenerate(self, review: Dict, entry: Dict) -> bool:
        """Determine if a review should be regenerated.

        Args:
            review: Generated review
            entry: Original entry

        Returns:
            True if should regenerate
        """
        confidence = self.calculate_confidence(review, entry)
        threshold = self.validation_config.get('min_confidence_threshold', 0.6)

        return confidence < threshold
