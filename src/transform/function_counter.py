"""Function counter using tree-sitter AST parsing."""

from __future__ import annotations

import logging
from typing import Optional

try:
    import tree_sitter_c as tsc
    import tree_sitter_cpp as tscpp
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser, QueryCursor
except ImportError:
    raise ImportError(
        "tree-sitter packages are required for function counting. "
        "Install with: uv add tree-sitter tree-sitter-c tree-sitter-cpp tree-sitter-java"
    )

logger = logging.getLogger(__name__)

# Initialize language objects (cached)
C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())
JAVA_LANGUAGE = Language(tsjava.language())


def count_functions_in_code(code: str, language: str) -> int:
    """
    Count function definitions in code using tree-sitter AST.

    Args:
        code: Source code string
        language: 'c/c++', 'c', 'c++', 'cpp', or 'java'

    Returns:
        Number of function definitions found
        -1 if parsing fails or language is unsupported
    """
    if not code or not code.strip():
        return 0

    # Normalize language name
    lang_normalized = language.lower().strip()

    try:
        # Select appropriate language and query
        if lang_normalized in ['c', 'c/c++', 'c++', 'cpp']:
            lang_obj = CPP_LANGUAGE  # Use C++ parser for all C/C++ variants
            # Query for function definitions
            query_str = "(function_definition) @func"

        elif lang_normalized == 'java':
            lang_obj = JAVA_LANGUAGE
            # Query for methods and constructors
            query_str = """
            [
              (method_declaration) @func
              (constructor_declaration) @func
            ]
            """
        else:
            logger.warning(f"Unsupported language for function counting: {language}")
            return -1

        # Create parser
        parser = Parser(lang_obj)

        # Parse code
        tree = parser.parse(bytes(code, 'utf8'))

        # Create query and cursor (2024 API)
        query = lang_obj.query(query_str)
        cursor = QueryCursor(query)

        # Execute query using QueryCursor.captures()
        captures = cursor.captures(tree.root_node)

        # Count function captures
        # captures returns a dict: {"func": [node1, node2...]}
        function_count = 0
        if isinstance(captures, dict):
            for tag in captures:
                function_count += len(captures[tag])
        else:
            # Fallback for older formats
            function_count = len(captures)

        logger.debug(
            f"Found {function_count} function(s) in {language} code "
            f"({len(code)} chars)"
        )

        return function_count

    except Exception as e:
        logger.warning(f"Failed to parse {language} code: {e}")
        return -1


def is_single_function(code: str, language: str) -> bool:
    """
    Check if code contains exactly one function definition.

    Args:
        code: Source code string
        language: 'c/c++', 'c', 'c++', 'cpp', or 'java'

    Returns:
        True if exactly 1 function, False otherwise
        False if parsing fails (per user requirement: delete parse failures)
    """
    try:
        count = count_functions_in_code(code, language)

        # Return True only if exactly 1 function
        # Return False for:
        #   - 0 functions (no function detected)
        #   - 2+ functions (multiple functions)
        #   - -1 (parse failure) - user requested to delete these
        return count == 1

    except Exception as e:
        logger.warning(f"Exception in is_single_function: {e}")
        # Per user requirement: delete samples that fail to parse
        return False


def get_function_count_stats(code_samples: list[tuple[str, str]]) -> dict:
    """
    Get statistics on function counts across multiple code samples.

    Args:
        code_samples: List of (code, language) tuples

    Returns:
        Dictionary with statistics:
        - total: total samples
        - single_function: count with exactly 1 function
        - multiple_functions: count with 2+ functions
        - no_functions: count with 0 functions
        - parse_failures: count that failed to parse
    """
    stats = {
        'total': len(code_samples),
        'single_function': 0,
        'multiple_functions': 0,
        'no_functions': 0,
        'parse_failures': 0
    }

    for code, language in code_samples:
        count = count_functions_in_code(code, language)

        if count == -1:
            stats['parse_failures'] += 1
        elif count == 0:
            stats['no_functions'] += 1
        elif count == 1:
            stats['single_function'] += 1
        else:  # count > 1
            stats['multiple_functions'] += 1

    return stats
