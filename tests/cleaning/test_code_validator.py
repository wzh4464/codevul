"""Tests for code_validator module."""

import csv
from pathlib import Path

import pytest

from src.cleaning.code_validator import CodeValidator


class TestCodeValidatorValidation:
    """Test cases for CodeValidator.validate_row method."""

    @pytest.fixture
    def default_validator(self, default_code_validator_config):
        """Create a default CodeValidator instance."""
        return CodeValidator(default_code_validator_config)

    # -------------------------------------------------------------------------
    # Valid Code Cases
    # -------------------------------------------------------------------------

    def test_validate_valid_code_pair(self, default_validator):
        """Test that valid code before and after passes."""
        row = {
            'code_before': 'int vuln() { return 0; }',  # > 10 chars
            'code_after': 'int fixed() { return 1; }',  # > 10 chars
        }
        assert default_validator.validate_row(row) is True

    def test_validate_long_code(self, default_validator):
        """Test that long code passes."""
        code = 'x' * 1000
        row = {
            'code_before': code,
            'code_after': code + 'y',  # Different
        }
        assert default_validator.validate_row(row) is True

    def test_validate_exactly_min_length(self, default_validator):
        """Test code exactly at minimum length."""
        row = {
            'code_before': 'x' * 10,
            'code_after': 'y' * 10,
        }
        assert default_validator.validate_row(row) is True

    # -------------------------------------------------------------------------
    # Empty Code Cases
    # -------------------------------------------------------------------------

    def test_validate_empty_code_before(self, default_validator):
        """Test that empty code_before is rejected."""
        row = {
            'code_before': '',
            'code_after': 'int fixed() { return 1; }',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_empty_code_after(self, default_validator):
        """Test that empty code_after is rejected."""
        row = {
            'code_before': 'int vuln() { return 0; }',
            'code_after': '',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_both_empty(self, default_validator):
        """Test that both empty codes are rejected."""
        row = {
            'code_before': '',
            'code_after': '',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_whitespace_only(self, default_validator):
        """Test that whitespace-only code is rejected."""
        row = {
            'code_before': '   \n\t   ',
            'code_after': 'int fixed() { return 1; }',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_missing_code_before(self, default_validator):
        """Test missing code_before field."""
        row = {
            'code_after': 'int fixed() { return 1; }',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_missing_code_after(self, default_validator):
        """Test missing code_after field."""
        row = {
            'code_before': 'int vuln() { return 0; }',
        }
        assert default_validator.validate_row(row) is False

    # -------------------------------------------------------------------------
    # Minimum Length Cases
    # -------------------------------------------------------------------------

    def test_validate_code_before_too_short(self, default_validator):
        """Test that code_before below minimum length is rejected."""
        row = {
            'code_before': 'short',  # 5 chars < 10
            'code_after': 'int fixed() { return 1; }',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_code_after_too_short(self, default_validator):
        """Test that code_after below minimum length is rejected."""
        row = {
            'code_before': 'int vuln() { return 0; }',
            'code_after': 'short',  # 5 chars < 10
        }
        assert default_validator.validate_row(row) is False

    def test_validate_both_too_short(self, default_validator):
        """Test that both codes below minimum length are rejected."""
        row = {
            'code_before': 'short',
            'code_after': 'tiny',
        }
        assert default_validator.validate_row(row) is False

    def test_validate_one_char_below_min(self, default_validator):
        """Test code one character below minimum."""
        row = {
            'code_before': 'x' * 9,  # 9 chars < 10
            'code_after': 'y' * 10,
        }
        assert default_validator.validate_row(row) is False

    # -------------------------------------------------------------------------
    # Identical Code Cases
    # -------------------------------------------------------------------------

    def test_validate_identical_code_rejected(self, default_validator):
        """Test that identical code_before and code_after is rejected."""
        code = 'int same() { return 1; }'
        row = {
            'code_before': code,
            'code_after': code,
        }
        assert default_validator.validate_row(row) is False

    def test_validate_almost_identical(self, default_validator):
        """Test that almost identical code passes."""
        row = {
            'code_before': 'int func() { return 0; }',
            'code_after': 'int func() { return 1; }',
        }
        assert default_validator.validate_row(row) is True

    def test_validate_identical_with_different_whitespace(self, default_validator):
        """Test identical code with different whitespace passes after strip."""
        row = {
            'code_before': '  int func() { return 1; }  ',
            'code_after': 'int func() { return 1; }',
        }
        # After strip, they're identical
        assert default_validator.validate_row(row) is False

    # -------------------------------------------------------------------------
    # Configuration Variants
    # -------------------------------------------------------------------------

    def test_validate_skip_empty_disabled(self):
        """Test with skip_empty disabled."""
        config = {'skip_empty': False, 'skip_identical': True, 'min_code_length': 10}
        validator = CodeValidator(config)

        row = {
            'code_before': '',
            'code_after': 'int fixed() { return 1; }',
        }
        # Empty is allowed, but still needs min length check
        # Empty string has length 0 < 10
        assert validator.validate_row(row) is False

    def test_validate_skip_identical_disabled(self):
        """Test with skip_identical disabled."""
        config = {'skip_empty': True, 'skip_identical': False, 'min_code_length': 10}
        validator = CodeValidator(config)

        code = 'int same() { return 1; }'
        row = {
            'code_before': code,
            'code_after': code,
        }
        assert validator.validate_row(row) is True

    def test_validate_custom_min_length(self):
        """Test with custom minimum length."""
        config = {'skip_empty': True, 'skip_identical': True, 'min_code_length': 5}
        validator = CodeValidator(config)

        row = {
            'code_before': 'abc12',  # 5 chars
            'code_after': 'def34',  # 5 chars
        }
        assert validator.validate_row(row) is True

    def test_validate_zero_min_length(self):
        """Test with zero minimum length."""
        config = {'skip_empty': False, 'skip_identical': False, 'min_code_length': 0}
        validator = CodeValidator(config)

        row = {
            'code_before': '',
            'code_after': '',
        }
        assert validator.validate_row(row) is True


class TestCodeValidatorProcess:
    """Test cases for CodeValidator.process method."""

    @pytest.fixture
    def default_validator(self, default_code_validator_config):
        """Create a default CodeValidator instance."""
        return CodeValidator(default_code_validator_config)

    def test_process_filters_invalid(self, default_validator, tmp_path):
        """Test that invalid rows are filtered."""
        input_path = tmp_path / "input.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['code_before', 'code_after', 'data'])
            writer.writeheader()
            # Valid
            writer.writerow({
                'code_before': 'int vuln() { return 0; }',
                'code_after': 'int fixed() { return 1; }',
                'data': 'a'
            })
            # Empty code_before
            writer.writerow({
                'code_before': '',
                'code_after': 'int fixed() { return 1; }',
                'data': 'b'
            })
            # Identical
            writer.writerow({
                'code_before': 'int same() { return 1; }',
                'code_after': 'int same() { return 1; }',
                'data': 'c'
            })
            # Too short
            writer.writerow({
                'code_before': 'short',
                'code_after': 'tiny',
                'data': 'd'
            })

        output_path = tmp_path / "output.csv"
        result = default_validator.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 4
        assert result.output_count == 1
        assert result.filtered_count == 3

        # Check output
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0]['data'] == 'a'

    def test_process_empty_csv(self, default_validator, tmp_path):
        """Test processing empty CSV."""
        input_path = tmp_path / "empty.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['code_before', 'code_after'])
            writer.writeheader()

        output_path = tmp_path / "output.csv"
        result = default_validator.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 0
        assert result.output_count == 0

    def test_process_all_valid(self, default_validator, tmp_path):
        """Test processing when all rows are valid."""
        input_path = tmp_path / "input.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['code_before', 'code_after'])
            writer.writeheader()
            for i in range(5):
                writer.writerow({
                    'code_before': f'int vuln{i}() {{ return 0; }}',
                    'code_after': f'int fixed{i}() {{ return 1; }}',
                })

        output_path = tmp_path / "output.csv"
        result = default_validator.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 5
        assert result.output_count == 5
        assert result.filtered_count == 0

    def test_process_file_not_found(self, default_validator, tmp_path):
        """Test processing non-existent file."""
        input_path = tmp_path / "nonexistent.csv"
        output_path = tmp_path / "output.csv"

        result = default_validator.process(input_path, output_path)

        assert result.success is False
        assert result.error is not None


class TestCodeValidatorConfiguration:
    """Test cases for CodeValidator configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        validator = CodeValidator(None)
        assert validator.skip_empty is True
        assert validator.skip_identical is True
        assert validator.min_length == 10

    def test_empty_config(self):
        """Test empty configuration uses defaults."""
        validator = CodeValidator({})
        assert validator.skip_empty is True
        assert validator.skip_identical is True
        assert validator.min_length == 10

    def test_partial_config(self):
        """Test partial configuration merges with defaults."""
        config = {'min_code_length': 20}
        validator = CodeValidator(config)

        assert validator.skip_empty is True  # Default
        assert validator.skip_identical is True  # Default
        assert validator.min_length == 20  # Custom


class TestCodeValidatorEdgeCases:
    """Edge case tests for CodeValidator."""

    @pytest.fixture
    def default_validator(self, default_code_validator_config):
        """Create a default CodeValidator instance."""
        return CodeValidator(default_code_validator_config)

    def test_validate_unicode_code(self, default_validator):
        """Test validation with unicode characters."""
        row = {
            'code_before': '// 中文注释\nint func() { return 0; }',
            'code_after': '// 日本語コメント\nint func() { return 1; }',
        }
        assert default_validator.validate_row(row) is True

    def test_validate_multiline_code(self, default_validator):
        """Test validation with multiline code."""
        code_before = '''
int func() {
    int x = 0;
    return x;
}
'''
        code_after = '''
int func() {
    int x = 1;
    return x;
}
'''
        row = {'code_before': code_before, 'code_after': code_after}
        assert default_validator.validate_row(row) is True

    def test_validate_special_characters(self, default_validator):
        """Test validation with special characters."""
        row = {
            'code_before': 'char* s = "hello\\nworld";',
            'code_after': 'char* s = "hello\\tworld";',
        }
        assert default_validator.validate_row(row) is True

    def test_validate_only_whitespace_difference(self, default_validator):
        """Test that only whitespace difference is treated as identical after strip."""
        row = {
            'code_before': 'int x = 1;',
            'code_after': 'int x = 1; ',  # Just trailing space
        }
        # After strip, they're identical
        assert default_validator.validate_row(row) is False
