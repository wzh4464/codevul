"""Tests for language_filter module."""

import csv
from pathlib import Path

import pytest

from src.cleaning.language_filter import LanguageFilter, LANGUAGE_MAPPING


class TestLanguageMapping:
    """Test the LANGUAGE_MAPPING constant."""

    def test_c_variants_map_correctly(self):
        """Test that C/C++ variants map to 'c/c++'."""
        c_variants = ['c', 'C', 'cpp', 'c++', 'C++', 'Cpp', 'CPP', 'C/C++']
        for variant in c_variants:
            assert LANGUAGE_MAPPING.get(variant) == 'c/c++', f"'{variant}' should map to 'c/c++'"

    def test_java_variants_map_correctly(self):
        """Test that Java variants map to 'java'."""
        java_variants = ['java', 'Java', 'JAVA']
        for variant in java_variants:
            assert LANGUAGE_MAPPING.get(variant) == 'java', f"'{variant}' should map to 'java'"

    def test_unknown_language_not_mapped(self):
        """Test that unknown languages are not in the mapping."""
        assert 'python' not in LANGUAGE_MAPPING
        assert 'ruby' not in LANGUAGE_MAPPING


class TestLanguageFilterValidation:
    """Test cases for LanguageFilter.validate_row method."""

    @pytest.fixture
    def default_filter(self, default_language_filter_config):
        """Create a default LanguageFilter instance."""
        return LanguageFilter(default_language_filter_config)

    # -------------------------------------------------------------------------
    # Valid Language Cases
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("language", [
        'c', 'C', 'cpp', 'c++', 'C++', 'Cpp', 'CPP', 'C/C++',
    ])
    def test_validate_c_variants_allowed(self, default_filter, language):
        """Test that C/C++ variants are allowed."""
        row = {'language': language}
        assert default_filter.validate_row(row) is True

    @pytest.mark.parametrize("language", [
        'java', 'Java', 'JAVA',
    ])
    def test_validate_java_variants_allowed(self, default_filter, language):
        """Test that Java variants are allowed."""
        row = {'language': language}
        assert default_filter.validate_row(row) is True

    # -------------------------------------------------------------------------
    # Invalid Language Cases
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("language", [
        'python', 'Python', 'PYTHON',
        'ruby', 'Ruby',
        'javascript', 'JavaScript',
        'go', 'Go',
        'rust', 'Rust',
    ])
    def test_validate_unsupported_languages(self, default_filter, language):
        """Test that unsupported languages are rejected."""
        row = {'language': language}
        assert default_filter.validate_row(row) is False

    def test_validate_empty_language(self, default_filter):
        """Test that empty language is rejected."""
        row = {'language': ''}
        assert default_filter.validate_row(row) is False

    def test_validate_whitespace_language(self, default_filter):
        """Test that whitespace-only language is rejected."""
        row = {'language': '   '}
        assert default_filter.validate_row(row) is False

    def test_validate_missing_language_field(self, default_filter):
        """Test that missing language field is rejected."""
        row = {'other': 'field'}
        assert default_filter.validate_row(row) is False

    # -------------------------------------------------------------------------
    # Custom Configuration Cases
    # -------------------------------------------------------------------------

    def test_validate_custom_allowed_list(self):
        """Test with custom allowed languages list."""
        config = {'allowed': ['python', 'ruby']}
        filter_instance = LanguageFilter(config)

        assert filter_instance.validate_row({'language': 'python'}) is True
        assert filter_instance.validate_row({'language': 'c'}) is False


class TestLanguageFilterTransform:
    """Test cases for LanguageFilter.transform_row method."""

    @pytest.fixture
    def default_filter(self, default_language_filter_config):
        """Create a default LanguageFilter instance."""
        return LanguageFilter(default_language_filter_config)

    @pytest.mark.parametrize("input_lang,expected_lang", [
        ('c', 'c/c++'),
        ('C', 'c/c++'),
        ('cpp', 'c/c++'),
        ('c++', 'c/c++'),
        ('C++', 'c/c++'),
        ('java', 'java'),
        ('Java', 'java'),
        ('JAVA', 'java'),
    ])
    def test_transform_normalizes_language(self, default_filter, input_lang, expected_lang):
        """Test that language is normalized in transform."""
        row = {'language': input_lang, 'other': 'data'}
        result = default_filter.transform_row(row)

        assert result['language'] == expected_lang
        assert result['other'] == 'data'  # Other fields preserved

    def test_transform_unknown_language_unchanged(self, default_filter):
        """Test that unknown languages are left unchanged."""
        row = {'language': 'python'}
        result = default_filter.transform_row(row)

        assert result['language'] == 'python'

    def test_transform_preserves_other_fields(self, default_filter):
        """Test that other row fields are preserved."""
        row = {
            'language': 'c',
            'code_before': 'int x;',
            'code_after': 'int y;',
            'cwe': 'CWE-79'
        }
        result = default_filter.transform_row(row)

        assert result['language'] == 'c/c++'
        assert result['code_before'] == 'int x;'
        assert result['code_after'] == 'int y;'
        assert result['cwe'] == 'CWE-79'


class TestLanguageFilterProcess:
    """Test cases for LanguageFilter.process method."""

    @pytest.fixture
    def default_filter(self, default_language_filter_config):
        """Create a default LanguageFilter instance."""
        return LanguageFilter(default_language_filter_config)

    def test_process_filters_and_transforms(self, default_filter, tmp_path):
        """Test that process filters and transforms correctly."""
        # Create input CSV
        input_path = tmp_path / "input.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['language', 'data'])
            writer.writeheader()
            writer.writerow({'language': 'c', 'data': 'a'})
            writer.writerow({'language': 'python', 'data': 'b'})  # Should be filtered
            writer.writerow({'language': 'Java', 'data': 'c'})

        output_path = tmp_path / "output.csv"
        result = default_filter.process(input_path, output_path)

        # Check result
        assert result.success is True
        assert result.input_count == 3
        assert result.output_count == 2
        assert result.filtered_count == 1

        # Check output file
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]['language'] == 'c/c++'
        assert rows[1]['language'] == 'java'

    def test_process_empty_csv(self, default_filter, tmp_path):
        """Test processing empty CSV (header only)."""
        input_path = tmp_path / "empty.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['language', 'data'])
            writer.writeheader()

        output_path = tmp_path / "output.csv"
        result = default_filter.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 0
        assert result.output_count == 0
        assert result.filtered_count == 0

    def test_process_all_filtered(self, default_filter, tmp_path):
        """Test processing when all rows are filtered."""
        input_path = tmp_path / "input.csv"
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['language', 'data'])
            writer.writeheader()
            writer.writerow({'language': 'python', 'data': 'a'})
            writer.writerow({'language': 'ruby', 'data': 'b'})

        output_path = tmp_path / "output.csv"
        result = default_filter.process(input_path, output_path)

        assert result.success is True
        assert result.input_count == 2
        assert result.output_count == 0
        assert result.filtered_count == 2

    def test_process_file_not_found(self, default_filter, tmp_path):
        """Test processing with non-existent input file."""
        input_path = tmp_path / "nonexistent.csv"
        output_path = tmp_path / "output.csv"

        result = default_filter.process(input_path, output_path)

        assert result.success is False
        assert result.error is not None

    def test_process_preserves_fieldnames(self, default_filter, tmp_path):
        """Test that all fieldnames are preserved in output."""
        input_path = tmp_path / "input.csv"
        fieldnames = ['language', 'code_before', 'code_after', 'cwe', 'commit_url']
        with open(input_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow({
                'language': 'c',
                'code_before': 'int x;',
                'code_after': 'int y;',
                'cwe': 'CWE-79',
                'commit_url': 'https://github.com/test'
            })

        output_path = tmp_path / "output.csv"
        default_filter.process(input_path, output_path)

        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            assert set(reader.fieldnames) == set(fieldnames)


class TestLanguageFilterConfiguration:
    """Test cases for LanguageFilter configuration handling."""

    def test_default_config(self):
        """Test that default config is used when None is passed."""
        filter_instance = LanguageFilter(None)
        # Should have default allowed list
        assert filter_instance.allowed is not None

    def test_empty_config(self):
        """Test with empty config dict."""
        filter_instance = LanguageFilter({})
        # Should use defaults
        assert filter_instance.allowed is not None

    def test_custom_mapping(self):
        """Test with custom language mapping."""
        config = {
            'allowed': ['custom'],
            'normalize_mapping': {'py': 'custom', 'python': 'custom'}
        }
        filter_instance = LanguageFilter(config)

        assert filter_instance.validate_row({'language': 'py'}) is True
        assert filter_instance.validate_row({'language': 'python'}) is True
        assert filter_instance.transform_row({'language': 'py'})['language'] == 'custom'
