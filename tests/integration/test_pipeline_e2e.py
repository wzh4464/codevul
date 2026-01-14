"""End-to-end integration tests for the pipeline."""

import csv
import json
from pathlib import Path

import pytest

from src.cleaning.language_filter import LanguageFilter
from src.cleaning.cwe_filter import CWEValidator
from src.cleaning.code_validator import CodeValidator
from src.transform.review_cleaner import clean_review_message
from src.utils.cwe_utils import normalize_cwe, get_cwd_for_cwe, load_cwd_mapping

# Import tree-sitter dependent modules only if available
try:
    from src.transform.function_counter import count_functions_in_code, is_single_function
    from src.transform.comment_remover import remove_comments
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    count_functions_in_code = None
    is_single_function = None
    remove_comments = None


class TestCleaningPipelineE2E:
    """End-to-end tests for the cleaning pipeline."""

    @pytest.fixture
    def sample_csv_data(self):
        """Sample data representing normalized output."""
        return [
            # Valid C entry
            {
                'cwe': 'CWE-79',
                'code_before': '''
int vulnerable_func(char *input) {
    char buffer[10];
    // Vulnerable: buffer overflow
    strcpy(buffer, input);
    return 0;
}
''',
                'code_after': '''
int fixed_func(char *input) {
    char buffer[10];
    // Fixed: bounds checking
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    return 0;
}
''',
                'commit_url': 'https://github.com/test/repo/commit/abc123',
                'language': 'c'
            },
            # Valid Java entry
            {
                'cwe': 'CWE-89',
                'code_before': '''
public class UserDao {
    public User getUser(String id) {
        String query = "SELECT * FROM users WHERE id = " + id;
        return execute(query);
    }
}
''',
                'code_after': '''
public class UserDao {
    public User getUser(String id) {
        String query = "SELECT * FROM users WHERE id = ?";
        return executePrepared(query, id);
    }
}
''',
                'commit_url': 'https://github.com/test/repo/commit/def456',
                'language': 'Java'
            },
            # Invalid: Python (should be filtered by language)
            {
                'cwe': 'CWE-22',
                'code_before': 'def vuln(): pass',
                'code_after': 'def fixed(): pass',
                'commit_url': 'https://github.com/test/repo/commit/ghi789',
                'language': 'python'
            },
            # Invalid: Unknown CWE
            {
                'cwe': 'Unknown',
                'code_before': 'int func() { return 0; }' * 3,
                'code_after': 'int func() { return 1; }' * 3,
                'commit_url': 'https://github.com/test/repo/commit/jkl012',
                'language': 'c'
            },
            # Invalid: Empty code_before
            {
                'cwe': 'CWE-125',
                'code_before': '',
                'code_after': 'int fixed() { return 1; }' * 3,
                'commit_url': 'https://github.com/test/repo/commit/mno345',
                'language': 'c'
            },
            # Invalid: Identical code
            {
                'cwe': 'CWE-787',
                'code_before': 'int same_func() { return 42; }',
                'code_after': 'int same_func() { return 42; }',
                'commit_url': 'https://github.com/test/repo/commit/pqr678',
                'language': 'c'
            },
        ]

    def test_full_cleaning_pipeline(self, sample_csv_data, tmp_path):
        """Test the complete cleaning pipeline from start to finish."""
        # Setup paths
        input_path = tmp_path / "normalized.csv"
        step1_output = tmp_path / "step1_language.csv"
        step2_output = tmp_path / "step2_cwe.csv"
        final_output = tmp_path / "cleaned.csv"

        # Write input CSV
        fieldnames = ['cwe', 'code_before', 'code_after', 'commit_url', 'language']
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in sample_csv_data:
                writer.writerow(row)

        # Step 1: Language Filter
        language_filter = LanguageFilter({'allowed': ['c/c++', 'java']})
        result1 = language_filter.process(input_path, step1_output)

        assert result1.success is True
        assert result1.input_count == 6
        # Python row should be filtered
        assert result1.filtered_count >= 1

        # Step 2: CWE Validator
        cwe_validator = CWEValidator({'reject_unknown': True, 'reject_invalid': True})
        result2 = cwe_validator.process(step1_output, step2_output)

        assert result2.success is True
        # Unknown CWE should be filtered
        assert result2.filtered_count >= 1

        # Step 3: Code Validator
        code_validator = CodeValidator({
            'skip_empty': True,
            'skip_identical': True,
            'min_code_length': 10
        })
        result3 = code_validator.process(step2_output, final_output)

        assert result3.success is True
        # Empty and identical code should be filtered

        # Verify final output
        with open(final_output, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            final_rows = list(reader)

        # Should have 2 valid entries (C and Java)
        assert len(final_rows) == 2

        # Verify normalization
        for row in final_rows:
            assert row['language'] in ['c/c++', 'java']
            assert row['cwe'].startswith('CWE-')
            assert len(row['code_before']) >= 10
            assert len(row['code_after']) >= 10
            assert row['code_before'] != row['code_after']


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed")
class TestTransformComponentsE2E:
    """End-to-end tests combining transform components."""

    def test_code_processing_pipeline(self, sample_c_code_with_comments):
        """Test processing code through comment removal and function counting."""
        # Step 1: Remove comments
        clean_code = remove_comments(sample_c_code_with_comments, 'c')

        # Verify comments are removed
        assert '//' not in clean_code
        assert '/*' not in clean_code

        # Step 2: Count functions
        func_count = count_functions_in_code(clean_code, 'c')

        # Should have exactly one function
        assert func_count == 1
        assert is_single_function(clean_code, 'c') is True

    def test_review_message_and_cwe_processing(self, mock_cwd_mapping):
        """Test processing review messages with CWE mapping."""
        # Sample review message in JSON format
        review_json = json.dumps([
            {"lang": "zh", "value": "修复SQL注入漏洞"},
            {"lang": "en", "value": "Fix SQL injection vulnerability"}
        ])

        # Step 1: Clean review message
        clean_message = clean_review_message(review_json)
        assert clean_message == "Fix SQL injection vulnerability"

        # Step 2: Process CWE
        raw_cwe = "cwe_89"
        normalized = normalize_cwe(raw_cwe)
        assert normalized == "CWE-89"

        # Step 3: Get CWD mapping
        cwd = get_cwd_for_cwe(normalized, mock_cwd_mapping)
        assert cwd == "CWD-1002"

    def test_multi_function_filtering(self):
        """Test filtering based on function count."""
        # Single function - should pass
        single_func_code = '''
int add(int a, int b) {
    return a + b;
}
'''
        # Multiple functions - should be filtered
        multi_func_code = '''
int add(int a, int b) {
    return a + b;
}

int subtract(int a, int b) {
    return a - b;
}
'''
        # Simulate filtering logic
        codes = [
            (single_func_code, 'c'),
            (multi_func_code, 'c'),
        ]

        filtered = [
            (code, lang) for code, lang in codes
            if is_single_function(code, lang)
        ]

        assert len(filtered) == 1
        assert filtered[0][0] == single_func_code


class TestCWDMappingE2E:
    """End-to-end tests for CWE to CWD mapping."""

    def test_load_and_use_mapping(self, mock_collect_json):
        """Test loading and using CWD mapping."""
        # Load mapping
        mapping = load_cwd_mapping(mock_collect_json)

        assert isinstance(mapping, dict)
        assert len(mapping) > 0

        # Test various CWE lookups
        test_cases = [
            ('CWE-79', 'CWD-1001'),
            ('cwe-79', 'CWD-1001'),  # Should normalize
            ('CWE-89', 'CWD-1002'),
            ('CWE-22', 'CWD-1004'),
        ]

        for cwe, expected_cwd in test_cases:
            result = get_cwd_for_cwe(cwe, mapping)
            assert result == expected_cwd, f"Expected {expected_cwd} for {cwe}, got {result}"

    def test_unknown_cwe_mapping(self, mock_collect_json):
        """Test that unknown CWEs return None."""
        mapping = load_cwd_mapping(mock_collect_json)

        unknown_cwes = ['CWE-999', 'Unknown', '', None]
        for cwe in unknown_cwes:
            result = get_cwd_for_cwe(cwe, mapping)
            assert result is None, f"Expected None for {cwe}, got {result}"


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed")
class TestDataFlowE2E:
    """Test data flow through the entire pipeline."""

    @pytest.fixture
    def realistic_vulnerability_data(self):
        """Realistic vulnerability data for testing."""
        return {
            'cwe': 'CWE-79|CWE-80',  # Multiple CWEs
            'code_before': '''
public class UserController {
    /**
     * Display user profile
     * @param name User name
     */
    public String showProfile(String name) {
        // Vulnerable: XSS
        return "<h1>Welcome, " + name + "</h1>";
    }
}
''',
            'code_after': '''
public class UserController {
    /**
     * Display user profile (fixed)
     * @param name User name
     */
    public String showProfile(String name) {
        // Fixed: HTML encoding
        return "<h1>Welcome, " + HtmlEncoder.encode(name) + "</h1>";
    }
}
''',
            'commit_url': 'https://github.com/example/app/commit/abc123def',
            'language': 'Java',
            'review_message': '[{"lang": "en", "value": "Fix XSS vulnerability in profile page"}]'
        }

    def test_complete_data_transformation(self, realistic_vulnerability_data, mock_cwd_mapping):
        """Test complete data transformation pipeline."""
        data = realistic_vulnerability_data

        # Step 1: Validate and normalize language
        language_filter = LanguageFilter({'allowed': ['c/c++', 'java']})
        assert language_filter.validate_row({'language': data['language']}) is True

        normalized_lang = language_filter.transform_row({'language': data['language']})
        assert normalized_lang['language'] == 'java'

        # Step 2: Validate and normalize CWE
        cwe_validator = CWEValidator({'reject_unknown': True})
        assert cwe_validator.validate_row({'cwe': data['cwe']}) is True

        transformed = cwe_validator.transform_row({'cwe': data['cwe']})
        assert 'CWE-79' in transformed['cwe']
        assert 'CWE-80' in transformed['cwe']

        # Step 3: Validate code
        code_validator = CodeValidator({'skip_empty': True, 'skip_identical': True})
        assert code_validator.validate_row({
            'code_before': data['code_before'],
            'code_after': data['code_after']
        }) is True

        # Step 4: Remove comments from code
        clean_before = remove_comments(data['code_before'], 'java')
        clean_after = remove_comments(data['code_after'], 'java')

        # Verify comments are removed
        assert '/**' not in clean_before
        assert '//' not in clean_before
        assert '/**' not in clean_after

        # Step 5: Count functions
        assert is_single_function(clean_before, 'java') is True
        assert is_single_function(clean_after, 'java') is True

        # Step 6: Process review message
        clean_review = clean_review_message(data['review_message'])
        assert clean_review == "Fix XSS vulnerability in profile page"

        # Step 7: Get CWD mapping for primary CWE
        primary_cwe = transformed['cwe'].split('|')[0]
        cwd = get_cwd_for_cwe(primary_cwe, mock_cwd_mapping)
        assert cwd == 'CWD-1001'  # CWE-79 maps to CWD-1001


class TestErrorHandlingE2E:
    """Test error handling across the pipeline."""

    def test_pipeline_handles_missing_files(self, tmp_path):
        """Test that pipeline handles missing files gracefully."""
        language_filter = LanguageFilter({})
        result = language_filter.process(
            tmp_path / "nonexistent.csv",
            tmp_path / "output.csv"
        )

        assert result.success is False
        assert result.error is not None

    def test_pipeline_handles_malformed_csv(self, tmp_path):
        """Test handling of malformed CSV data."""
        # Create a CSV with inconsistent columns
        input_path = tmp_path / "malformed.csv"
        with open(input_path, 'w', encoding='utf-8') as f:
            f.write("col1,col2,col3\n")
            f.write("a,b,c\n")
            f.write("d,e\n")  # Missing column

        language_filter = LanguageFilter({})
        result = language_filter.process(input_path, tmp_path / "output.csv")

        # Should handle gracefully (either success with partial data or failure)
        # The exact behavior depends on implementation
        assert isinstance(result.success, bool)

    @pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed")
    def test_transform_handles_invalid_language(self):
        """Test that transform functions handle invalid languages."""
        code = "int x = 1;"

        # Comment remover should return original for unsupported language
        result = remove_comments(code, 'unsupported')
        assert result == code

        # Function counter should return -1 for unsupported language
        count = count_functions_in_code(code, 'unsupported')
        assert count == -1

        # is_single_function should return False for unsupported language
        assert is_single_function(code, 'unsupported') is False
