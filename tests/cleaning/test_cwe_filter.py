"""Tests for cwe_filter module."""

import csv
from pathlib import Path

import pytest

from src.cleaning.cwe_filter import CWEValidator


class TestCWEValidatorValidation:
    """Test cases for CWEValidator.validate_row method."""

    @pytest.fixture
    def default_validator(self, default_cwe_filter_config):
        """Create a default CWEValidator instance."""
        return CWEValidator(default_cwe_filter_config)

    # -------------------------------------------------------------------------
    # Valid CWE Cases
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("cwe", [
        'CWE-79',
        'CWE-89',
        'CWE-125',
        'cwe-79',
        'CWE_79',
    ])
    def test_validate_valid_single_cwe(self, default_validator, cwe):
        """Test that valid single CWEs pass validation."""
        row = {'cwe': cwe}
        assert default_validator.validate_row(row) is True

    def test_validate_multiple_cwes_pipe_separated(self, default_validator):
        """Test that multiple pipe-separated CWEs pass validation."""
        row = {'cwe': 'CWE-79|CWE-89|CWE-125'}
        assert default_validator.validate_row(row) is True

    def test_validate_multiple_cwes_with_spaces(self, default_validator):
        """Test that multiple CWEs with spaces pass validation."""
        row = {'cwe': 'CWE-79 | CWE-89 | CWE-125'}
        assert default_validator.validate_row(row) is True

    # -------------------------------------------------------------------------
    # Invalid/Unknown CWE Cases
    # -------------------------------------------------------------------------

    def test_validate_unknown_cwe_rejected(self, default_validator):
        """Test that 'Unknown' CWE is rejected."""
        row = {'cwe': 'Unknown'}
        assert default_validator.validate_row(row) is False

    def test_validate_unknown_case_insensitive(self, default_validator):
        """Test that 'unknown' variants are rejected."""
        for unknown in ['Unknown', 'UNKNOWN', 'unknown']:
            row = {'cwe': unknown}
            assert default_validator.validate_row(row) is False

    def test_validate_empty_cwe_rejected(self, default_validator):
        """Test that empty CWE is rejected."""
        row = {'cwe': ''}
        assert default_validator.validate_row(row) is False

    def test_validate_whitespace_cwe_rejected(self, default_validator):
        """Test that whitespace-only CWE is rejected."""
        row = {'cwe': '   '}
        assert default_validator.validate_row(row) is False

    def test_validate_missing_cwe_field_rejected(self, default_validator):
        """Test that missing CWE field is rejected."""
        row = {'other': 'field'}
        assert default_validator.validate_row(row) is False

    def test_validate_multiple_cwes_one_unknown(self, default_validator):
        """Test that if any CWE is unknown, row is rejected."""
        row = {'cwe': 'CWE-79|Unknown|CWE-89'}
        assert default_validator.validate_row(row) is False

    # -------------------------------------------------------------------------
    # Configuration Variants
    # -------------------------------------------------------------------------

    def test_validate_accept_unknown_when_configured(self):
        """Test that unknown CWEs are accepted when configured."""
        config = {'reject_unknown': False, 'reject_invalid': True}
        validator = CWEValidator(config)

        row = {'cwe': 'Unknown'}
        assert validator.validate_row(row) is True

    def test_validate_accept_empty_when_configured(self):
        """Test that empty CWEs are accepted when configured."""
        config = {'reject_unknown': True, 'reject_invalid': False}
        validator = CWEValidator(config)

        row = {'cwe': ''}
        assert validator.validate_row(row) is True

    def test_validate_accept_all_when_configured(self):
        """Test that all CWEs are accepted when both flags are False."""
        config = {'reject_unknown': False, 'reject_invalid': False}
        validator = CWEValidator(config)

        assert validator.validate_row({'cwe': ''}) is True
        assert validator.validate_row({'cwe': 'Unknown'}) is True
        assert validator.validate_row({'cwe': 'CWE-79'}) is True


class TestCWEValidatorTransform:
    """Test cases for CWEValidator.transform_row method."""

    @pytest.fixture
    def default_validator(self, default_cwe_filter_config):
        """Create a default CWEValidator instance."""
        return CWEValidator(default_cwe_filter_config)

    def test_transform_normalizes_cwe(self, default_validator):
        """Test that CWE is normalized in transform."""
        row = {'cwe': 'cwe_79'}
        result = default_validator.transform_row(row)
        assert result['cwe'] == 'CWE-79'

    def test_transform_normalizes_multiple_cwes(self, default_validator):
        """Test that multiple CWEs are normalized."""
        row = {'cwe': 'cwe_79|CWE-89|cwe 125'}
        result = default_validator.transform_row(row)

        cwes = result['cwe'].split('|')
        assert 'CWE-79' in cwes
        assert 'CWE-89' in cwes
        assert 'CWE-125' in cwes

    def test_transform_filters_unknown_cwes(self, default_validator):
        """Test that unknown CWEs are filtered out."""
        row = {'cwe': 'CWE-79|Unknown|CWE-89'}
        result = default_validator.transform_row(row)

        cwes = result['cwe'].split('|')
        assert 'Unknown' not in cwes
        assert 'CWE-79' in cwes
        assert 'CWE-89' in cwes

    def test_transform_preserves_other_fields(self, default_validator):
        """Test that other fields are preserved."""
        row = {'cwe': 'CWE-79', 'data': 'value', 'other': 'field'}
        result = default_validator.transform_row(row)

        assert result['data'] == 'value'
        assert result['other'] == 'field'

    def test_transform_empty_cwe_unchanged(self, default_validator):
        """Test that empty CWE is left unchanged."""
        row = {'cwe': ''}
        result = default_validator.transform_row(row)
        assert result['cwe'] == ''

    def test_transform_removes_whitespace(self, default_validator):
        """Test that whitespace is removed from CWEs."""
        row = {'cwe': '  CWE-79  |  CWE-89  '}
        result = default_validator.transform_row(row)

        cwes = result['cwe'].split('|')
        assert 'CWE-79' in cwes
        assert 'CWE-89' in cwes


class TestCWEValidatorProcess:
    """Test cases for CWEValidator.process method."""

    @pytest.fixture
    def default_validator(self, default_cwe_filter_config):
        """Create a default CWEValidator instance."""
        return CWEValidator(default_cwe_filter_config)

    def test_process_filters_and_transforms(self, default_validator, tmp_path):
        """Test that process filters invalid CWEs and transforms valid ones."""
        input_path = tmp_path / "input.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['cwe', 'data'])
            writer.writeheader()
            writer.writerow({'cwe': 'cwe_79', 'data': 'a'})
            writer.writerow({'cwe': 'Unknown', 'data': 'b'})  # Should be filtered
            writer.writerow({'cwe': 'CWE-89', 'data': 'c'})
            writer.writerow({'cwe': '', 'data': 'd'})  # Should be filtered

        output_path = tmp_path / "output.csv"
        result = default_validator.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 4
        assert result.output_count == 2
        assert result.filtered_count == 2

        # Check output
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]['cwe'] == 'CWE-79'  # Normalized
        assert rows[1]['cwe'] == 'CWE-89'

    def test_process_multiple_cwes_filtered(self, default_validator, tmp_path):
        """Test processing rows with multiple CWEs."""
        input_path = tmp_path / "input.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['cwe', 'data'])
            writer.writeheader()
            writer.writerow({'cwe': 'CWE-79|CWE-89', 'data': 'a'})
            writer.writerow({'cwe': 'CWE-79|Unknown', 'data': 'b'})  # Should be filtered

        output_path = tmp_path / "output.csv"
        result = default_validator.process(input_path, output_path)

        assert result.success is True
        assert result.output_count == 1

    def test_process_empty_csv(self, default_validator, tmp_path):
        """Test processing empty CSV."""
        input_path = tmp_path / "empty.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['cwe', 'data'])
            writer.writeheader()

        output_path = tmp_path / "output.csv"
        result = default_validator.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 0
        assert result.output_count == 0

    def test_process_file_not_found(self, default_validator, tmp_path):
        """Test processing with non-existent file."""
        input_path = tmp_path / "nonexistent.csv"
        output_path = tmp_path / "output.csv"

        result = default_validator.process(input_path, output_path)

        assert result.success is False
        assert result.error is not None


class TestCWEValidatorConfiguration:
    """Test cases for CWEValidator configuration."""

    def test_default_config(self):
        """Test default configuration."""
        validator = CWEValidator(None)
        assert validator.reject_unknown is True
        assert validator.reject_invalid is True

    def test_empty_config(self):
        """Test empty configuration uses defaults."""
        validator = CWEValidator({})
        assert validator.reject_unknown is True
        assert validator.reject_invalid is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = {'reject_unknown': False, 'reject_invalid': False}
        validator = CWEValidator(config)
        assert validator.reject_unknown is False
        assert validator.reject_invalid is False


class TestCWEValidatorEdgeCases:
    """Edge case tests for CWEValidator."""

    @pytest.fixture
    def default_validator(self, default_cwe_filter_config):
        """Create a default CWEValidator instance."""
        return CWEValidator(default_cwe_filter_config)

    def test_validate_only_pipes(self, default_validator):
        """Test CWE with only pipe separators."""
        row = {'cwe': '|||'}
        assert default_validator.validate_row(row) is False

    def test_transform_all_unknown_cwes(self, default_validator):
        """Test transform when all CWEs are unknown."""
        row = {'cwe': 'Unknown|UNKNOWN'}
        result = default_validator.transform_row(row)
        assert result['cwe'] == ''

    def test_validate_numeric_cwe(self, default_validator):
        """Test validation with numeric CWE (should still work)."""
        row = {'cwe': '79'}
        assert default_validator.validate_row(row) is True

    def test_transform_numeric_cwe(self, default_validator):
        """Test transform with numeric string CWE - returned as-is since pattern requires 'cwe' prefix."""
        row = {'cwe': '79'}
        result = default_validator.transform_row(row)
        # Pure numeric strings are not auto-prefixed by normalize_cwe
        assert result['cwe'] == '79'
