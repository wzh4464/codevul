"""Code structure extraction for different programming languages."""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple


def extract_c_cpp_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract class and function names from C/C++ code."""
    # Class pattern (struct or class)
    class_pattern = r'(?:struct|class)\s+(\w+)'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # Function pattern
    func_pattern = r'\b(\w+)\s*\([^)]*\)\s*\{'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(1) if func_match else None

    return class_name, func_name


def extract_java_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract class and function names from Java code."""
    # Class pattern
    class_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:class|interface|enum)\s+(\w+)'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # Method pattern
    func_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(1) if func_match else None

    return class_name, func_name


def extract_structure(code: str, language: str) -> Dict[str, Optional[str]]:
    """
    Extract code structure based on language.

    Args:
        code: Source code
        language: Programming language ('c/c++' or 'java')

    Returns:
        Dictionary with 'context', 'class', and 'func' keys
    """
    if not code:
        return {'context': None, 'class': None, 'func': None}

    class_name = None
    func_name = None

    # Extract based on language
    if language == 'c/c++':
        class_name, func_name = extract_c_cpp_structure(code)
    elif language == 'java':
        class_name, func_name = extract_java_structure(code)

    return {
        'context': code if code else None,
        'class': class_name,
        'func': code if func_name else None  # Full function code if function detected
    }
