"""Clean review_message field to extract plain text."""

from __future__ import annotations

import ast
import json
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


def clean_review_message(message: Optional[str]) -> Optional[str]:
    """
    Clean review_message to extract plain text.

    Handles:
    - JSON array format: [{'lang': 'en', 'value': '...'}]
    - Already plain text

    Returns:
        Plain text message or None
    """
    if not message or not message.strip():
        return None

    message = message.strip()

    # Try to parse as JSON array
    if message.startswith('['):
        try:
            # Try json.loads first
            data = json.loads(message)
            return _extract_from_list(data)
        except json.JSONDecodeError:
            pass

        try:
            # Try ast.literal_eval for Python dict syntax
            data = ast.literal_eval(message)
            return _extract_from_list(data)
        except (ValueError, SyntaxError):
            pass

    # Already plain text
    return message


def _extract_from_list(data: list) -> Optional[str]:
    """Extract value from list of lang/value dicts, preferring English."""
    if not isinstance(data, list) or not data:
        return None

    # Prefer English
    for item in data:
        if isinstance(item, dict):
            if item.get('lang') == 'en' and item.get('value'):
                return item['value'].strip()

    # Fallback to first value
    for item in data:
        if isinstance(item, dict) and item.get('value'):
            return item['value'].strip()

    return None
