"""Tests for cwe_utils module."""

import json
from collections import Counter

import pytest

from src.utils.cwe_utils import (
    normalize_cwe,
    extract_cwe_number,
    is_valid_cwe,
    is_unknown_cwe,
    group_by_cwe,
    count_cwes,
    get_cwe_statistics,
    split_by_cwe_size,
    filter_by_cwe,
    load_cwd_mapping,
    get_cwd_for_cwe,
    get_all_cwds_for_cwe,
)


class TestNormalizeCwe:
    """Test cases for normalize_cwe function."""

    # -------------------------------------------------------------------------
    # Standard Format Cases
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("input_cwe,expected", [
        # Standard format
        ("CWE-79", "CWE-79"),
        ("CWE-89", "CWE-89"),
        ("CWE-125", "CWE-125"),
        ("CWE-1", "CWE-1"),

        # Lowercase
        ("cwe-79", "CWE-79"),
        ("cwe-89", "CWE-89"),

        # With underscore
        ("CWE_79", "CWE-79"),
        ("cwe_89", "CWE-89"),

        # With space
        ("CWE 79", "CWE-79"),
        ("cwe 89", "CWE-89"),

        # Just number (string) - not auto-prefixed, returned as-is
        ("79", "79"),
        ("125", "125"),

        # Integer input
        (79, "CWE-79"),
        (89, "CWE-89"),
        (1, "CWE-1"),

        # Leading zeros
        ("CWE-079", "CWE-79"),
        ("CWE-0089", "CWE-89"),
    ])
    def test_normalize_various_formats(self, input_cwe, expected):
        """Test normalization of various CWE formats."""
        result = normalize_cwe(input_cwe)
        assert result == expected

    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------

    def test_normalize_none(self):
        """Test normalize with None input."""
        result = normalize_cwe(None)
        assert result == ""

    def test_normalize_empty_string(self):
        """Test normalize with empty string."""
        result = normalize_cwe("")
        assert result == ""

    def test_normalize_whitespace(self):
        """Test normalize with whitespace."""
        result = normalize_cwe("   ")
        assert result == ""

    def test_normalize_with_surrounding_whitespace(self):
        """Test normalize with surrounding whitespace."""
        result = normalize_cwe("  CWE-79  ")
        assert result == "CWE-79"

    def test_normalize_unknown(self):
        """Test normalize with 'Unknown' value."""
        result = normalize_cwe("Unknown")
        assert result == "Unknown"  # Returns as-is if no CWE pattern found

    def test_normalize_invalid_format(self):
        """Test normalize with invalid format (no number)."""
        result = normalize_cwe("not-a-cwe")
        assert result == "not-a-cwe"  # Returns as-is


class TestExtractCweNumber:
    """Test cases for extract_cwe_number function."""

    @pytest.mark.parametrize("input_cwe,expected", [
        # Standard formats
        ("CWE-79", 79),
        ("CWE-89", 89),
        ("cwe-125", 125),
        ("CWE_79", 79),
        ("CWE 79", 79),

        # Just numbers
        ("79", 79),
        ("125", 125),

        # With text around
        ("Some CWE-79 text", 79),
    ])
    def test_extract_valid_cwe(self, input_cwe, expected):
        """Test extraction of valid CWE numbers."""
        result = extract_cwe_number(input_cwe)
        assert result == expected

    @pytest.mark.parametrize("input_cwe", [
        None,
        "",
        "Unknown",
        "not-a-cwe",
        "CWE-",
        "CWE",
    ])
    def test_extract_invalid_cwe(self, input_cwe):
        """Test extraction returns None for invalid input."""
        result = extract_cwe_number(input_cwe)
        assert result is None


class TestIsValidCwe:
    """Test cases for is_valid_cwe function."""

    @pytest.mark.parametrize("input_cwe", [
        "CWE-79",
        "cwe-89",
        "CWE_125",
        "79",
        "125",
    ])
    def test_valid_cwes(self, input_cwe):
        """Test that valid CWEs return True."""
        assert is_valid_cwe(input_cwe) is True

    @pytest.mark.parametrize("input_cwe", [
        "",
        "Unknown",
        "not-a-cwe",
        "CWE-",
    ])
    def test_invalid_cwes(self, input_cwe):
        """Test that invalid CWEs return False."""
        assert is_valid_cwe(input_cwe) is False


class TestIsUnknownCwe:
    """Test cases for is_unknown_cwe function."""

    @pytest.mark.parametrize("input_cwe", [
        "Unknown",
        "UNKNOWN",
        "unknown",
        "",
        None,
        "   ",
    ])
    def test_unknown_cwes(self, input_cwe):
        """Test that unknown/invalid CWEs return True."""
        assert is_unknown_cwe(input_cwe) is True

    @pytest.mark.parametrize("input_cwe", [
        "CWE-79",
        "cwe-89",
        "CWE_125",
        "79",
    ])
    def test_known_cwes(self, input_cwe):
        """Test that valid CWEs return False."""
        assert is_unknown_cwe(input_cwe) is False


class TestGroupByCwe:
    """Test cases for group_by_cwe function."""

    def test_group_simple(self):
        """Test simple grouping by CWE."""
        items = [
            {"cwe": "CWE-79", "data": "a"},
            {"cwe": "CWE-79", "data": "b"},
            {"cwe": "CWE-89", "data": "c"},
        ]
        result = group_by_cwe(items)

        assert len(result) == 2
        assert len(result["CWE-79"]) == 2
        assert len(result["CWE-89"]) == 1

    def test_group_with_normalization(self):
        """Test grouping normalizes CWE identifiers."""
        items = [
            {"cwe": "CWE-79", "data": "a"},
            {"cwe": "cwe-79", "data": "b"},
            {"cwe": "CWE_79", "data": "c"},
        ]
        result = group_by_cwe(items, normalize=True)

        assert len(result) == 1
        assert len(result["CWE-79"]) == 3

    def test_group_without_normalization(self):
        """Test grouping without normalization."""
        items = [
            {"cwe": "CWE-79", "data": "a"},
            {"cwe": "cwe-79", "data": "b"},
        ]
        result = group_by_cwe(items, normalize=False)

        assert len(result) == 2
        assert "CWE-79" in result
        assert "cwe-79" in result

    def test_group_custom_field(self):
        """Test grouping with custom CWE field name."""
        items = [
            {"custom_cwe": "CWE-79", "data": "a"},
            {"custom_cwe": "CWE-89", "data": "b"},
        ]
        result = group_by_cwe(items, cwe_field="custom_cwe")

        assert "CWE-79" in result
        assert "CWE-89" in result

    def test_group_missing_field(self):
        """Test grouping with missing CWE field."""
        items = [
            {"cwe": "CWE-79"},
            {"other": "field"},  # Missing cwe
        ]
        result = group_by_cwe(items)

        assert "CWE-79" in result
        assert "Unknown" in result

    def test_group_empty_input(self):
        """Test grouping with empty input."""
        result = group_by_cwe([])
        assert result == {}


class TestCountCwes:
    """Test cases for count_cwes function."""

    def test_count_simple(self):
        """Test simple CWE counting."""
        items = [
            {"cwe": "CWE-79"},
            {"cwe": "CWE-79"},
            {"cwe": "CWE-89"},
        ]
        result = count_cwes(items)

        assert result["CWE-79"] == 2
        assert result["CWE-89"] == 1

    def test_count_with_normalization(self):
        """Test counting normalizes CWEs."""
        items = [
            {"cwe": "CWE-79"},
            {"cwe": "cwe-79"},
            {"cwe": "CWE_79"},
        ]
        result = count_cwes(items, normalize=True)

        assert result["CWE-79"] == 3

    def test_count_exclude_unknown(self):
        """Test counting with unknown exclusion."""
        items = [
            {"cwe": "CWE-79"},
            {"cwe": "Unknown"},
            {"cwe": ""},
        ]
        result = count_cwes(items, exclude_unknown=True)

        assert result["CWE-79"] == 1
        assert "Unknown" not in result
        assert "" not in result

    def test_count_include_unknown(self):
        """Test counting without unknown exclusion."""
        items = [
            {"cwe": "CWE-79"},
            {"cwe": "Unknown"},
        ]
        result = count_cwes(items, exclude_unknown=False)

        assert result["CWE-79"] == 1
        assert result["Unknown"] == 1


class TestGetCweStatistics:
    """Test cases for get_cwe_statistics function."""

    def test_statistics_basic(self):
        """Test basic statistics generation."""
        items = [
            {"cwe": "CWE-79"},
            {"cwe": "CWE-79"},
            {"cwe": "CWE-89"},
            {"cwe": "Unknown"},
        ]
        stats = get_cwe_statistics(items)

        assert stats["total_items"] == 4
        assert stats["unique_cwes"] == 3
        assert stats["unknown_count"] == 1
        assert stats["valid_count"] == 3
        assert isinstance(stats["cwe_counts"], Counter)
        assert len(stats["most_common"]) <= 10

    def test_statistics_empty_input(self):
        """Test statistics with empty input."""
        stats = get_cwe_statistics([])

        assert stats["total_items"] == 0
        assert stats["unique_cwes"] == 0
        assert stats["unknown_count"] == 0

    def test_statistics_generator_input(self):
        """Test statistics with generator input."""
        def items_gen():
            yield {"cwe": "CWE-79"}
            yield {"cwe": "CWE-89"}

        stats = get_cwe_statistics(items_gen())

        assert stats["total_items"] == 2


class TestSplitByCweSize:
    """Test cases for split_by_cwe_size function."""

    def test_split_basic(self):
        """Test basic size splitting."""
        items_by_cwe = {
            "CWE-79": list(range(6000)),   # Large
            "CWE-89": list(range(500)),    # Medium
            "CWE-22": list(range(50)),     # Small
        }
        large, medium, small = split_by_cwe_size(items_by_cwe)

        assert "CWE-79" in large
        assert "CWE-89" in medium
        assert "CWE-22" in small

    def test_split_custom_thresholds(self):
        """Test splitting with custom thresholds."""
        items_by_cwe = {
            "CWE-79": list(range(200)),
            "CWE-89": list(range(50)),
        }
        large, medium, small = split_by_cwe_size(
            items_by_cwe,
            large_threshold=100,
            medium_threshold=30
        )

        assert "CWE-79" in large
        assert "CWE-89" in medium

    def test_split_empty(self):
        """Test splitting empty input."""
        large, medium, small = split_by_cwe_size({})

        assert large == {}
        assert medium == {}
        assert small == {}


class TestFilterByCwe:
    """Test cases for filter_by_cwe function."""

    def test_filter_basic(self):
        """Test basic filtering."""
        items = [
            {"cwe": "CWE-79", "data": "a"},
            {"cwe": "CWE-89", "data": "b"},
            {"cwe": "CWE-22", "data": "c"},
        ]
        result = filter_by_cwe(items, ["CWE-79", "CWE-89"])

        assert len(result) == 2
        assert all(item["cwe"] in ["CWE-79", "CWE-89"] for item in result)

    def test_filter_with_normalization(self):
        """Test filtering normalizes both input and items."""
        items = [
            {"cwe": "cwe-79", "data": "a"},
            {"cwe": "CWE_89", "data": "b"},
        ]
        result = filter_by_cwe(items, ["CWE-79", "CWE-89"], normalize=True)

        assert len(result) == 2

    def test_filter_no_matches(self):
        """Test filtering with no matches."""
        items = [{"cwe": "CWE-79"}]
        result = filter_by_cwe(items, ["CWE-999"])

        assert len(result) == 0


class TestLoadCwdMapping:
    """Test cases for load_cwd_mapping function."""

    def test_load_mapping_basic(self, mock_collect_json):
        """Test basic mapping loading."""
        mapping = load_cwd_mapping(mock_collect_json)

        assert isinstance(mapping, dict)
        assert "CWE-79" in mapping
        assert "CWE-89" in mapping
        assert "CWD-1001" in mapping["CWE-79"]

    def test_load_mapping_normalizes_cwe(self, mock_collect_json):
        """Test that CWE identifiers are normalized."""
        mapping = load_cwd_mapping(mock_collect_json)

        # The mock has "79" as well as "CWE-79", should be normalized
        assert "CWE-79" in mapping

    def test_load_mapping_handles_children(self, mock_collect_json):
        """Test that nested children are processed."""
        mapping = load_cwd_mapping(mock_collect_json)

        # CWE-89 should have both CWD-1002 and CWD-1003 (from children)
        assert "CWE-89" in mapping
        cwds = mapping["CWE-89"]
        assert "CWD-1002" in cwds
        assert "CWD-1003" in cwds


class TestGetCwdForCwe:
    """Test cases for get_cwd_for_cwe function."""

    def test_get_cwd_basic(self, mock_cwd_mapping):
        """Test basic CWD retrieval."""
        result = get_cwd_for_cwe("CWE-79", mock_cwd_mapping)
        assert result == "CWD-1001"

    def test_get_cwd_first_of_multiple(self, mock_cwd_mapping):
        """Test that first CWD is returned when multiple exist."""
        result = get_cwd_for_cwe("CWE-89", mock_cwd_mapping)
        assert result == "CWD-1002"  # First one

    def test_get_cwd_normalizes_input(self, mock_cwd_mapping):
        """Test that input CWE is normalized."""
        result = get_cwd_for_cwe("cwe-79", mock_cwd_mapping)
        assert result == "CWD-1001"

    def test_get_cwd_not_found(self, mock_cwd_mapping):
        """Test CWD not found returns None."""
        result = get_cwd_for_cwe("CWE-999", mock_cwd_mapping)
        assert result is None

    def test_get_cwd_unknown_input(self, mock_cwd_mapping):
        """Test unknown CWE returns None."""
        result = get_cwd_for_cwe("Unknown", mock_cwd_mapping)
        assert result is None

    def test_get_cwd_empty_input(self, mock_cwd_mapping):
        """Test empty input returns None."""
        result = get_cwd_for_cwe("", mock_cwd_mapping)
        assert result is None


class TestGetAllCwdsForCwe:
    """Test cases for get_all_cwds_for_cwe function."""

    def test_get_all_cwds_single(self, mock_cwd_mapping):
        """Test getting single CWD."""
        result = get_all_cwds_for_cwe("CWE-79", mock_cwd_mapping)
        assert result == ["CWD-1001"]

    def test_get_all_cwds_multiple(self, mock_cwd_mapping):
        """Test getting multiple CWDs."""
        result = get_all_cwds_for_cwe("CWE-89", mock_cwd_mapping)
        assert len(result) == 2
        assert "CWD-1002" in result
        assert "CWD-1003" in result

    def test_get_all_cwds_not_found(self, mock_cwd_mapping):
        """Test not found returns empty list."""
        result = get_all_cwds_for_cwe("CWE-999", mock_cwd_mapping)
        assert result == []

    def test_get_all_cwds_unknown(self, mock_cwd_mapping):
        """Test unknown CWE returns empty list."""
        result = get_all_cwds_for_cwe("Unknown", mock_cwd_mapping)
        assert result == []
