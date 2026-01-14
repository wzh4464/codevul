"""Tests for comment_remover module."""

import pytest

# Skip entire module if tree-sitter is not available
try:
    from src.transform.comment_remover import remove_comments, _clean_whitespace
except ImportError:
    pytest.skip("tree-sitter not available", allow_module_level=True)


class TestRemoveComments:
    """Test cases for remove_comments function."""

    # -------------------------------------------------------------------------
    # Normal Cases: C/C++ Comments
    # -------------------------------------------------------------------------

    def test_remove_c_line_comments(self):
        """Test removing C++ style line comments."""
        code = '''int add(int a, int b) {
    // This is a line comment
    return a + b;
}'''
        result = remove_comments(code, 'c')

        assert '//' not in result
        assert 'This is a line comment' not in result
        assert 'return a + b;' in result
        assert 'int add(int a, int b)' in result

    def test_remove_c_block_comments(self):
        """Test removing C style block comments."""
        code = '''int add(int a, int b) {
    /* This is a
       block comment */
    return a + b;
}'''
        result = remove_comments(code, 'c')

        assert '/*' not in result
        assert '*/' not in result
        assert 'block comment' not in result
        assert 'return a + b;' in result

    def test_remove_inline_comments(self):
        """Test removing inline comments."""
        code = '''int x = 1;  // inline comment
int y = 2;  /* another inline */'''
        result = remove_comments(code, 'c++')

        assert 'inline comment' not in result
        assert 'another inline' not in result
        assert 'int x = 1;' in result
        assert 'int y = 2;' in result

    def test_remove_mixed_comments(self, sample_c_code_with_comments):
        """Test removing mixed comment types."""
        result = remove_comments(sample_c_code_with_comments, 'c')

        assert '//' not in result
        assert '/*' not in result
        assert '*/' not in result
        assert 'return a + b;' in result

    # -------------------------------------------------------------------------
    # Normal Cases: Java Comments
    # -------------------------------------------------------------------------

    def test_remove_java_line_comments(self):
        """Test removing Java line comments."""
        code = '''public int add(int a, int b) {
    // Java line comment
    return a + b;
}'''
        result = remove_comments(code, 'java')

        assert '//' not in result
        assert 'Java line comment' not in result
        assert 'return a + b;' in result

    def test_remove_java_block_comments(self):
        """Test removing Java block comments."""
        code = '''public int add(int a, int b) {
    /* Java block comment */
    return a + b;
}'''
        result = remove_comments(code, 'java')

        assert '/*' not in result
        assert 'Java block comment' not in result
        assert 'return a + b;' in result

    def test_remove_javadoc_comments(self):
        """Test removing Javadoc comments."""
        code = '''/**
 * This is a Javadoc comment
 * @param a first number
 */
public int add(int a, int b) {
    return a + b;
}'''
        result = remove_comments(code, 'java')

        assert '/**' not in result
        assert 'Javadoc' not in result
        assert '@param' not in result
        assert 'public int add' in result

    # -------------------------------------------------------------------------
    # Language Variants
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("language", [
        'c',
        'C',
        'c++',
        'C++',
        'cpp',
        'Cpp',
        'CPP',
        'c/c++',
        'C/C++',
    ])
    def test_c_language_variants(self, language):
        """Test that various C/C++ language strings are accepted."""
        code = '''int x = 1; // comment'''
        result = remove_comments(code, language)

        assert '//' not in result
        assert 'comment' not in result
        assert 'int x = 1;' in result

    @pytest.mark.parametrize("language", [
        'java',
        'Java',
        'JAVA',
    ])
    def test_java_language_variants(self, language):
        """Test that various Java language strings are accepted."""
        code = '''int x = 1; // comment'''
        result = remove_comments(code, language)

        assert '//' not in result
        assert 'int x = 1;' in result

    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------

    def test_empty_code(self):
        """Test with empty string input."""
        result = remove_comments('', 'c')
        assert result == ''

    def test_whitespace_only_code(self):
        """Test with whitespace-only input."""
        code = '   \n\t\n   '
        result = remove_comments(code, 'c')
        assert result == code  # Should return original

    def test_code_without_comments(self):
        """Test code that has no comments."""
        code = '''int add(int a, int b) {
    return a + b;
}'''
        result = remove_comments(code, 'c')

        # Should be essentially the same (possibly with whitespace cleanup)
        assert 'return a + b;' in result
        assert 'int add' in result

    def test_only_comments(self):
        """Test code that is only comments."""
        code = '''// Just a comment
/* Another comment */'''
        result = remove_comments(code, 'c')

        # Should be empty or just whitespace
        assert '//' not in result
        assert '/*' not in result

    # -------------------------------------------------------------------------
    # Error Handling
    # -------------------------------------------------------------------------

    def test_unsupported_language(self):
        """Test with unsupported language - should return original code."""
        code = '''def add(a, b):
    # Python comment
    return a + b'''
        result = remove_comments(code, 'python')

        # Should return original code unchanged
        assert result == code

    def test_unsupported_language_ruby(self):
        """Test with another unsupported language."""
        code = '''def add(a, b)
  # Ruby comment
  a + b
end'''
        result = remove_comments(code, 'ruby')
        assert result == code

    def test_none_language(self):
        """Test with empty language string."""
        code = 'int x = 1; // comment'
        result = remove_comments(code, '')

        # Empty string is unsupported, should return original
        assert result == code


class TestCleanWhitespace:
    """Test cases for _clean_whitespace helper function."""

    def test_remove_empty_lines(self):
        """Test removing excessive empty lines."""
        code = '''int x = 1;



int y = 2;'''
        result = _clean_whitespace(code)

        # Should have at most one empty line between code
        lines = result.split('\n')
        consecutive_empty = 0
        for line in lines:
            if not line.strip():
                consecutive_empty += 1
            else:
                consecutive_empty = 0
            assert consecutive_empty <= 1

    def test_remove_trailing_empty_lines(self):
        """Test removing trailing empty lines."""
        code = '''int x = 1;


'''
        result = _clean_whitespace(code)

        # Should not end with empty lines
        assert not result.endswith('\n\n')
        assert result.strip() == result or result.endswith('\n') and result.rstrip() + '\n' == result

    def test_preserve_single_empty_lines(self):
        """Test preserving single empty lines between code."""
        code = '''int x = 1;

int y = 2;'''
        result = _clean_whitespace(code)

        assert 'int x = 1;' in result
        assert 'int y = 2;' in result

    def test_whitespace_only_lines(self):
        """Test handling lines with only whitespace."""
        code = '''int x = 1;

int y = 2;'''
        result = _clean_whitespace(code)

        # Lines with only whitespace should be treated as empty
        assert 'int x = 1;' in result
        assert 'int y = 2;' in result

    def test_empty_input(self):
        """Test with empty input."""
        result = _clean_whitespace('')
        assert result == ''

    def test_no_changes_needed(self):
        """Test code that doesn't need changes."""
        code = '''int x = 1;
int y = 2;'''
        result = _clean_whitespace(code)

        assert result == code


class TestRemoveCommentsIntegration:
    """Integration tests combining comment removal with whitespace cleanup."""

    def test_full_c_file_cleanup(self):
        """Test cleaning a full C file with various comments."""
        code = '''// Header comment
#include <stdio.h>

/* Block comment explaining
   the function below */
int add(int a, int b) {
    // Add two numbers
    return a + b;  /* inline */
}

// Another function
int subtract(int a, int b) {
    return a - b;
}
'''
        result = remove_comments(code, 'c')

        # All comments should be removed
        assert '//' not in result
        assert '/*' not in result
        assert '*/' not in result
        assert 'Header comment' not in result
        assert 'Block comment' not in result

        # Code should be preserved
        assert '#include <stdio.h>' in result
        assert 'int add(int a, int b)' in result
        assert 'return a + b;' in result
        assert 'int subtract(int a, int b)' in result

    def test_full_java_file_cleanup(self, sample_java_code_with_comments):
        """Test cleaning a full Java file."""
        result = remove_comments(sample_java_code_with_comments, 'java')

        assert '//' not in result
        assert '/*' not in result
        assert '/**' not in result
        assert 'Line comment' not in result
        assert 'Block comment' not in result
        assert 'Javadoc' not in result

        assert 'public class Calculator' in result
        assert 'public int add' in result
