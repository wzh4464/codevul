"""Tests for function_counter module using pytest."""

import pytest

# Skip entire module if tree-sitter is not available
try:
    from src.transform.function_counter import (
        count_functions_in_code,
        is_single_function,
        get_function_count_stats,
    )
except ImportError:
    pytest.skip("tree-sitter not available", allow_module_level=True)


class TestCountFunctionsInCode:
    """Test cases for count_functions_in_code function."""

    # -------------------------------------------------------------------------
    # C/C++ Function Counting
    # -------------------------------------------------------------------------

    def test_count_single_c_function(self):
        """Test counting a single C function."""
        code = '''
int add(int a, int b) {
    return a + b;
}
'''
        assert count_functions_in_code(code, 'c') == 1

    def test_count_multiple_c_functions(self):
        """Test counting multiple C functions."""
        code = '''
int add(int a, int b) {
    return a + b;
}

int subtract(int a, int b) {
    return a - b;
}

int multiply(int a, int b) {
    return a * b;
}
'''
        assert count_functions_in_code(code, 'c') == 3

    def test_count_cpp_class_methods(self):
        """Test counting C++ class methods."""
        code = '''
class Calculator {
public:
    int add(int a, int b) {
        return a + b;
    }

    int subtract(int a, int b) {
        return a - b;
    }
};
'''
        assert count_functions_in_code(code, 'cpp') == 2

    def test_count_cpp_single_method(self, sample_java_class):
        """Test counting single C++ method."""
        code = '''
class Calculator {
public:
    int add(int a, int b) {
        return a + b;
    }
};
'''
        assert count_functions_in_code(code, 'c++') == 1

    # -------------------------------------------------------------------------
    # Java Method Counting
    # -------------------------------------------------------------------------

    def test_count_single_java_method(self):
        """Test counting a single Java method."""
        code = '''
public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
}
'''
        assert count_functions_in_code(code, 'java') == 1

    def test_count_multiple_java_methods(self):
        """Test counting multiple Java methods."""
        code = '''
public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }

    public int subtract(int a, int b) {
        return a - b;
    }
}
'''
        assert count_functions_in_code(code, 'java') == 2

    def test_count_java_constructor_and_method(self):
        """Test counting Java constructor and method."""
        code = '''
public class Calculator {
    public Calculator() {
        // Constructor
    }

    public int add(int a, int b) {
        return a + b;
    }
}
'''
        assert count_functions_in_code(code, 'java') == 2

    def test_count_java_static_methods(self):
        """Test counting Java static methods."""
        code = '''
public class Utility {
    public static int add(int a, int b) {
        return a + b;
    }

    private static int helper() {
        return 0;
    }
}
'''
        assert count_functions_in_code(code, 'java') == 2

    # -------------------------------------------------------------------------
    # Language Variants
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("language", [
        'c', 'C', 'c++', 'C++', 'cpp', 'Cpp', 'CPP', 'c/c++', 'C/C++',
    ])
    def test_c_language_variants(self, language):
        """Test that various C/C++ language strings work."""
        code = 'int func() { return 0; }'
        result = count_functions_in_code(code, language)
        assert result == 1

    @pytest.mark.parametrize("language", [
        'java', 'Java', 'JAVA',
    ])
    def test_java_language_variants(self, language):
        """Test that various Java language strings work."""
        code = 'public class A { public void m() {} }'
        result = count_functions_in_code(code, language)
        assert result == 1

    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------

    def test_count_empty_code(self):
        """Test counting in empty code returns 0."""
        assert count_functions_in_code('', 'c') == 0

    def test_count_whitespace_only(self):
        """Test counting in whitespace-only code returns 0."""
        assert count_functions_in_code('   \n\t  ', 'c') == 0

    def test_count_no_functions(self):
        """Test counting code with no functions."""
        code = '''
#include <stdio.h>
int x = 1;
int y = 2;
'''
        assert count_functions_in_code(code, 'c') == 0

    def test_count_unsupported_language(self):
        """Test unsupported language returns -1."""
        code = 'def func(): pass'
        assert count_functions_in_code(code, 'python') == -1

    def test_count_empty_language(self):
        """Test empty language string returns -1."""
        code = 'int func() { return 0; }'
        assert count_functions_in_code(code, '') == -1

    # -------------------------------------------------------------------------
    # Complex Cases
    # -------------------------------------------------------------------------

    def test_count_nested_functions_cpp(self):
        """Test counting with lambda functions in C++."""
        code = '''
int main() {
    auto lambda = []() { return 42; };
    return lambda();
}
'''
        # Main function should be counted; lambda behavior depends on parser
        result = count_functions_in_code(code, 'cpp')
        assert result >= 1

    def test_count_function_with_comments(self):
        """Test counting functions with comments."""
        code = '''
// This is a comment
int func() {
    /* Block comment */
    return 0;
}
'''
        assert count_functions_in_code(code, 'c') == 1


class TestIsSingleFunction:
    """Test cases for is_single_function function."""

    def test_single_function_returns_true(self):
        """Test that single function returns True."""
        code = 'int func() { return 0; }'
        assert is_single_function(code, 'c') is True

    def test_multiple_functions_returns_false(self):
        """Test that multiple functions return False."""
        code = '''
int func1() { return 0; }
int func2() { return 1; }
'''
        assert is_single_function(code, 'c') is False

    def test_no_functions_returns_false(self):
        """Test that no functions returns False."""
        code = 'int x = 1;'
        assert is_single_function(code, 'c') is False

    def test_empty_code_returns_false(self):
        """Test that empty code returns False."""
        assert is_single_function('', 'c') is False

    def test_unsupported_language_returns_false(self):
        """Test that unsupported language returns False."""
        code = 'def func(): pass'
        assert is_single_function(code, 'python') is False

    @pytest.mark.parametrize("code,language,expected", [
        ('int f() { return 0; }', 'c', True),
        ('int f() {} int g() {}', 'c', False),
        ('', 'c', False),
        ('int x;', 'c', False),
        ('public class A { void m() {} }', 'java', True),
        ('public class A { void m() {} void n() {} }', 'java', False),
    ])
    def test_is_single_function_parametrized(self, code, language, expected):
        """Parametrized test for is_single_function."""
        assert is_single_function(code, language) is expected


class TestGetFunctionCountStats:
    """Test cases for get_function_count_stats function."""

    def test_stats_basic(self):
        """Test basic statistics calculation."""
        samples = [
            ('int f() { return 0; }', 'c'),  # Single
            ('int f() {} int g() {}', 'c'),  # Multiple
            ('int x = 1;', 'c'),  # No functions
        ]
        stats = get_function_count_stats(samples)

        assert stats['total'] == 3
        assert stats['single_function'] == 1
        assert stats['multiple_functions'] == 1
        assert stats['no_functions'] == 1
        assert stats['parse_failures'] == 0

    def test_stats_with_parse_failures(self):
        """Test statistics with unsupported languages."""
        samples = [
            ('int f() { return 0; }', 'c'),  # Single
            ('def func(): pass', 'python'),  # Parse failure (unsupported)
        ]
        stats = get_function_count_stats(samples)

        assert stats['total'] == 2
        assert stats['single_function'] == 1
        assert stats['parse_failures'] == 1

    def test_stats_empty_input(self):
        """Test statistics with empty input."""
        stats = get_function_count_stats([])

        assert stats['total'] == 0
        assert stats['single_function'] == 0
        assert stats['multiple_functions'] == 0
        assert stats['no_functions'] == 0
        assert stats['parse_failures'] == 0

    def test_stats_all_single(self):
        """Test statistics when all samples have single functions."""
        samples = [
            ('int f() { return 0; }', 'c'),
            ('int g() { return 1; }', 'c'),
            ('public class A { void m() {} }', 'java'),
        ]
        stats = get_function_count_stats(samples)

        assert stats['total'] == 3
        assert stats['single_function'] == 3
        assert stats['multiple_functions'] == 0

    def test_stats_all_multiple(self):
        """Test statistics when all samples have multiple functions."""
        samples = [
            ('int f() {} int g() {}', 'c'),
            ('int a() {} int b() {} int c() {}', 'c'),
        ]
        stats = get_function_count_stats(samples)

        assert stats['total'] == 2
        assert stats['single_function'] == 0
        assert stats['multiple_functions'] == 2


class TestFunctionCounterIntegration:
    """Integration tests for function counter module."""

    def test_real_c_vulnerability_code(self):
        """Test with realistic vulnerable C code."""
        code = '''
int vulnerable_copy(char *dest, const char *src) {
    // Vulnerable: no bounds checking
    strcpy(dest, src);
    return strlen(dest);
}
'''
        assert count_functions_in_code(code, 'c') == 1
        assert is_single_function(code, 'c') is True

    def test_real_java_vulnerability_code(self):
        """Test with realistic vulnerable Java code."""
        code = '''
public class UserService {
    public User getUser(String id) {
        // Vulnerable: SQL injection
        String query = "SELECT * FROM users WHERE id = " + id;
        return executeQuery(query);
    }

    private User executeQuery(String query) {
        // Execute query
        return null;
    }
}
'''
        assert count_functions_in_code(code, 'java') == 2
        assert is_single_function(code, 'java') is False

    def test_function_counter_with_fixtures(self, sample_single_c_function, sample_multiple_c_functions):
        """Test using fixtures."""
        assert is_single_function(sample_single_c_function, 'c') is True
        assert is_single_function(sample_multiple_c_functions, 'c') is False

    def test_mixed_language_samples(self):
        """Test statistics with mixed language samples."""
        samples = [
            ('int f() { return 0; }', 'c'),
            ('public class A { void m() {} }', 'java'),
            ('int a() {} int b() {}', 'cpp'),
            ('', 'c'),  # Empty
        ]
        stats = get_function_count_stats(samples)

        assert stats['total'] == 4
        assert stats['single_function'] == 2
        assert stats['multiple_functions'] == 1
        assert stats['no_functions'] == 1
