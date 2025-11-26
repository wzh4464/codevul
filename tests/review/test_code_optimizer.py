import unittest
import os
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from review.code_optimizer import CodeOptimizer

class TestCodeOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = CodeOptimizer(context_lines=3)

    def test_optimize_code_pair_simple_change(self):
        vulnerable_code = """
def add(a, b):
    # This is a vulnerable comment
    return a - b  # Bug: should be addition
"""
        benign_code = """
def add(a, b):
    # This is a fixed comment
    return a + b
"""
        optimized_result = self.optimizer.optimize_code_pair(vulnerable_code, benign_code)
        self.assertTrue(optimized_result['optimized'])
        self.assertIn(">>>    2 |     # This is a vulnerable comment", optimized_result['vulnerable_code'])
        self.assertIn(">>>    3 |     return a - b  # Bug: should be addition", optimized_result['vulnerable_code'])
        self.assertIn(">>>    2 |     # This is a fixed comment", optimized_result['benign_code'])
        self.assertIn(">>>    3 |     return a + b", optimized_result['benign_code'])
        self.assertIn("   1 | def add(a, b):", optimized_result['vulnerable_code'])

    def test_optimize_code_pair_insertion(self):
        vulnerable_code = """
def foo():
    print("hello")
"""
        benign_code = """
def foo():
    print("hello")
    # New line inserted
    print("world")
"""
        optimized_result = self.optimizer.optimize_code_pair(vulnerable_code, benign_code)
        self.assertTrue(optimized_result['optimized'])
        self.assertIn("   1 | def foo():", optimized_result['vulnerable_code']) # Full original content
        self.assertIn("   2 |     print(\"hello\")", optimized_result['vulnerable_code'])
        self.assertIn(">>>    3 |     # New line inserted", optimized_result['benign_code'])
        self.assertIn(">>>    4 |     print(\"world\")", optimized_result['benign_code'])
        self.assertIn("   2 |     print(\"hello\")", optimized_result['benign_code'])


    def test_optimize_code_pair_deletion(self):
        vulnerable_code = """
def bar():
    print("line 1")
    print("line 2 - delete me")
    print("line 3")
"""
        benign_code = """
def bar():
    print("line 1")
    print("line 3")
"""
        optimized_result = self.optimizer.optimize_code_pair(vulnerable_code, benign_code)
        self.assertTrue(optimized_result['optimized'])
        self.assertIn(">>>    3 |     print(\"line 2 - delete me\")", optimized_result['vulnerable_code'])
        self.assertIn("   2 |     print(\"line 1\")", optimized_result['vulnerable_code'])
        self.assertIn("   3 |     print(\"line 3\")", optimized_result['benign_code'])

    def test_optimize_code_pair_no_change(self):
        code = """
def same_code():
    pass
"""
        optimized_result = self.optimizer.optimize_code_pair(code, code)
        self.assertTrue(optimized_result['optimized'])
        self.assertIn('No significant changes detected', optimized_result['note'])
        self.assertEqual(optimized_result['vulnerable_code'], code[:200] + '...' if len(code) > 200 else code)
        self.assertEqual(optimized_result['benign_code'], code[:200] + '...' if len(code) > 200 else code)


    def test_optimize_entry(self):
        entry = {
            "vulnerable_code": {
                "func": "def vuln_func():\n    x = 1\n    y = 2 # vuln\n    z = x + y",
                "language": "python"
            },
            "benign_code": {
                "func": "def vuln_func():\n    x = 1\n    y = 3 # benign\n    z = x + y",
                "language": "python"
            },
            "other_data": "some_value"
        }
        optimized_entry = self.optimizer.optimize_entry(entry)
        self.assertTrue(optimized_entry['_optimization']['enabled'])
        self.assertIn(">>>    3 |     y = 2 # vuln", optimized_entry['vulnerable_code']['context'])
        self.assertIn(">>>    3 |     y = 3 # benign", optimized_entry['benign_code']['context'])
        self.assertIsNotNone(optimized_entry['vulnerable_code']['_original_size'])

    def test_create_unified_diff_view(self):
        vulnerable_code = "line1\nline2_vuln\nline3"
        benign_code = "line1\nline2_benign\nline3"
        diff_view = self.optimizer.create_unified_diff_view(vulnerable_code, benign_code, "old.py", "new.py")
        self.assertIn("--- old.py", diff_view)
        self.assertIn("+++ new.py", diff_view)
        self.assertIn("-line2_vuln", diff_view)
        self.assertIn("+line2_benign", diff_view)
        self.assertIn(" line1", diff_view)
        self.assertIn(" line3", diff_view)

    def test_extract_code_from_field(self):
        self.assertEqual(self.optimizer._extract_code_from_field("just a string"), "just a string")
        self.assertEqual(self.optimizer._extract_code_from_field({"code": "dict code"}), "dict code")
        self.assertEqual(self.optimizer._extract_code_from_field({"func": "func code"}), "func code")
        self.assertEqual(self.optimizer._extract_code_from_field({"context": "context code"}), "context code")
        self.assertEqual(self.optimizer._extract_code_from_field({"unknown": "no code"}), "")
        self.assertEqual(self.optimizer._extract_code_from_field(None), "")
        self.assertEqual(self.optimizer._extract_code_from_field(123), "")


if __name__ == '__main__':
    unittest.main()
