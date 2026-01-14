"""Remove comments from code using tree-sitter AST parsing."""

from __future__ import annotations

import logging
import re
from typing import Optional

try:
    import tree_sitter_c as tsc
    import tree_sitter_cpp as tscpp
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser
except ImportError:
    raise ImportError(
        "tree-sitter packages are required. "
        "Install with: uv add tree-sitter tree-sitter-c tree-sitter-cpp tree-sitter-java"
    )

logger = logging.getLogger(__name__)

# Initialize language objects (cached)
C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())
JAVA_LANGUAGE = Language(tsjava.language())


def remove_comments(code: str, language: str) -> str:
    """
    Remove all comments from code using tree-sitter AST.

    Args:
        code: Source code string
        language: 'c/c++', 'c', 'c++', 'cpp', or 'java'

    Returns:
        Code with comments removed
        Original code if parsing fails
    """
    if not code or not code.strip():
        return code

    lang_normalized = language.lower().strip()

    try:
        # Select language
        if lang_normalized in ['c', 'c/c++', 'c++', 'cpp']:
            lang_obj = CPP_LANGUAGE
        elif lang_normalized == 'java':
            lang_obj = JAVA_LANGUAGE
        else:
            logger.warning(f"Unsupported language for comment removal: {language}")
            return code

        parser = Parser(lang_obj)
        tree = parser.parse(bytes(code, 'utf8'))

        # Collect all comment nodes
        comments = []
        _collect_comments(tree.root_node, comments)

        if not comments:
            return code

        # Sort by start position (descending) to remove from end first
        comments.sort(key=lambda n: n.start_byte, reverse=True)

        # Remove comments
        code_bytes = code.encode('utf8')
        for node in comments:
            code_bytes = code_bytes[:node.start_byte] + code_bytes[node.end_byte:]

        result = code_bytes.decode('utf8')

        # Clean up empty lines and excessive whitespace
        result = _clean_whitespace(result)

        return result

    except Exception as e:
        logger.warning(f"Failed to remove comments from {language} code: {e}")
        return code


def _collect_comments(node, comments: list):
    """Recursively collect all comment nodes."""
    if node.type in ('comment', 'line_comment', 'block_comment'):
        comments.append(node)

    for child in node.children:
        _collect_comments(child, comments)


def _clean_whitespace(code: str) -> str:
    """Clean up whitespace after comment removal."""
    # Remove lines that are now empty or only whitespace
    lines = code.split('\n')
    cleaned_lines = []

    for line in lines:
        # Keep non-empty lines
        if line.strip():
            cleaned_lines.append(line)
        # Keep single empty lines between code
        elif cleaned_lines and cleaned_lines[-1].strip():
            cleaned_lines.append('')

    # Remove trailing empty lines
    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()

    return '\n'.join(cleaned_lines)
