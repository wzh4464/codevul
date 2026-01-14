"""Shared pytest fixtures for CodeVul tests."""

import csv
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

import pytest

# Add project root and src to Python path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))


# =============================================================================
# Code Sample Fixtures
# =============================================================================

@pytest.fixture
def sample_c_code_with_comments() -> str:
    """C code sample with various comment types."""
    return '''
int add(int a, int b) {
    // This is a line comment
    /* This is a block comment */
    return a + b;  // inline comment
}
'''


@pytest.fixture
def sample_c_code_without_comments() -> str:
    """Expected C code after comment removal."""
    return '''int add(int a, int b) {
    return a + b;
}'''


@pytest.fixture
def sample_java_code_with_comments() -> str:
    """Java code sample with various comment types."""
    return '''
public class Calculator {
    // Line comment
    /* Block comment */
    /**
     * Javadoc comment
     */
    public int add(int a, int b) {
        return a + b;  // inline
    }
}
'''


@pytest.fixture
def sample_single_c_function() -> str:
    """C code with a single function."""
    return '''
int add(int a, int b) {
    return a + b;
}
'''


@pytest.fixture
def sample_multiple_c_functions() -> str:
    """C code with multiple functions."""
    return '''
int add(int a, int b) {
    return a + b;
}

int subtract(int a, int b) {
    return a - b;
}
'''


@pytest.fixture
def sample_java_class() -> str:
    """Java class with methods."""
    return '''
public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
}
'''


# =============================================================================
# CSV Fixtures
# =============================================================================

@pytest.fixture
def tmp_csv_file(tmp_path):
    """Factory fixture to create temporary CSV files."""
    def _create_csv(filename: str, rows: List[Dict], fieldnames: List[str] = None):
        filepath = tmp_path / filename
        if not fieldnames and rows:
            fieldnames = list(rows[0].keys())

        with open(filepath, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        return filepath

    return _create_csv


@pytest.fixture
def sample_cleaning_csv_data() -> List[Dict]:
    """Sample data for cleaning step tests."""
    return [
        {
            'cwe': 'CWE-79',
            'code_before': 'int vuln() { return 0; }' * 5,
            'code_after': 'int fixed() { return 1; }' * 5,
            'commit_url': 'https://github.com/test/repo/commit/abc123',
            'language': 'c'
        },
        {
            'cwe': 'CWE-89',
            'code_before': 'public void vuln() {}' * 5,
            'code_after': 'public void fixed() {}' * 5,
            'commit_url': 'https://github.com/test/repo/commit/def456',
            'language': 'java'
        },
        {
            'cwe': 'Unknown',
            'code_before': 'void test() {}' * 5,
            'code_after': 'void test2() {}' * 5,
            'commit_url': 'https://github.com/test/repo/commit/ghi789',
            'language': 'c++'
        },
    ]


# =============================================================================
# CWE/CWD Mapping Fixtures
# =============================================================================

@pytest.fixture
def mock_cwd_mapping() -> Dict[str, List[str]]:
    """Mock CWE to CWD mapping."""
    return {
        'CWE-79': ['CWD-1001'],
        'CWE-89': ['CWD-1002', 'CWD-1003'],
        'CWE-22': ['CWD-1004'],
        'CWE-125': ['CWD-1005'],
    }


@pytest.fixture
def mock_collect_json(tmp_path) -> Path:
    """Create a mock collect.json file."""
    data = {
        "Security": {
            "items": [
                {
                    "id": "CWD-1001",
                    "cwe": ["CWE-79", "79"],
                    "children": []
                },
                {
                    "id": "CWD-1002",
                    "cwe": ["CWE-89"],
                    "children": [
                        {
                            "id": "CWD-1003",
                            "cwe": ["CWE-89"],
                            "children": []
                        }
                    ]
                }
            ]
        },
        "Memory": {
            "items": [
                {
                    "id": "CWD-1004",
                    "cwe": ["CWE-22"],
                    "children": []
                }
            ]
        }
    }

    filepath = tmp_path / "collect.json"
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    return filepath


# =============================================================================
# Cleaning Config Fixtures
# =============================================================================

@pytest.fixture
def default_language_filter_config() -> Dict:
    """Default configuration for LanguageFilter."""
    return {
        'allowed': ['c/c++', 'java'],
    }


@pytest.fixture
def default_cwe_filter_config() -> Dict:
    """Default configuration for CWEValidator."""
    return {
        'reject_unknown': True,
        'reject_invalid': True,
    }


@pytest.fixture
def default_code_validator_config() -> Dict:
    """Default configuration for CodeValidator."""
    return {
        'skip_empty': True,
        'skip_identical': True,
        'min_code_length': 10,
    }


# =============================================================================
# JSON Fixtures
# =============================================================================

@pytest.fixture
def tmp_json_file(tmp_path):
    """Factory fixture to create temporary JSON files."""
    def _create_json(filename: str, data):
        filepath = tmp_path / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return filepath

    return _create_json


@pytest.fixture
def sample_benchmark_data() -> Dict:
    """Sample benchmark data structure."""
    return {
        "c/c++": {
            "CWD-1001": [
                {
                    "benign_code": {"context": "int fixed() { return 1; }", "func": None},
                    "vulnerable_code": {"context": "int vuln() { return 0; }", "func": None},
                    "source": "cvefixes",
                    "commit_url": "https://github.com/test/repo/commit/abc",
                    "CWE": "CWE-79",
                    "other_CWEs": [],
                    "other_CWDs": [],
                    "CVE": None
                }
            ]
        },
        "java": {
            "CWD-1002": [
                {
                    "benign_code": {"context": "public void fixed() {}", "func": None},
                    "vulnerable_code": {"context": "public void vuln() {}", "func": None},
                    "source": "primevul",
                    "commit_url": "https://github.com/test/repo/commit/def",
                    "CWE": "CWE-89",
                    "other_CWEs": [],
                    "other_CWDs": [],
                    "CVE": "CVE-2023-12345"
                }
            ]
        }
    }
