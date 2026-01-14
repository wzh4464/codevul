#!/usr/bin/env python3
"""Check random samples from filtered benchmark to verify requirements."""

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.transform.function_counter import count_functions_in_code

def check_samples(json_path: Path, num_samples: int = 60):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Collect all entries with their language
    all_entries = []
    for language, cwd_dict in data.items():
        for cwd_id, entries in cwd_dict.items():
            for entry in entries:
                all_entries.append((language, cwd_id, entry))

    print(f"Total entries: {len(all_entries)}")

    # Random sample
    samples = random.sample(all_entries, min(num_samples, len(all_entries)))

    passed = 0
    failed = 0

    for i, (language, cwd_id, entry) in enumerate(samples, 1):
        benign_func = entry.get('benign_code', {}).get('func')
        vuln_func = entry.get('vulnerable_code', {}).get('func')
        benign_context = entry.get('benign_code', {}).get('context')
        vuln_context = entry.get('vulnerable_code', {}).get('context')

        # Check function counts
        benign_count = count_functions_in_code(benign_func, language) if benign_func else 0
        vuln_count = count_functions_in_code(vuln_func, language) if vuln_func else 0

        # Determine pass/fail
        benign_ok = benign_func is None or benign_count == 1
        vuln_ok = vuln_func is None or vuln_count == 1

        if benign_ok and vuln_ok:
            passed += 1
            status = "✓ PASS"
        else:
            failed += 1
            status = "✗ FAIL"

        print(f"\n{'='*70}")
        print(f"Sample {i}: {status}")
        print(f"Language: {language}, CWD: {cwd_id}")
        print(f"Source: {entry.get('source')}")

        # Show benign func info
        if benign_func:
            lines = benign_func.count('\n') + 1
            print(f"\nBenign func: {benign_count} function(s), {lines} lines")
            print(f"First 200 chars: {benign_func[:200]}...")
        else:
            print(f"\nBenign func: None")

        # Show benign context info
        if benign_context:
            ctx_lines = benign_context.count('\n') + 1
            print(f"Benign context: {ctx_lines} lines")

        # Show vulnerable func info
        if vuln_func:
            lines = vuln_func.count('\n') + 1
            print(f"\nVulnerable func: {vuln_count} function(s), {lines} lines")
            print(f"First 200 chars: {vuln_func[:200]}...")
        else:
            print(f"\nVulnerable func: None")

        # Show vulnerable context info
        if vuln_context:
            ctx_lines = vuln_context.count('\n') + 1
            print(f"Vulnerable context: {ctx_lines} lines")

    print(f"\n{'='*70}")
    print(f"SUMMARY: {passed}/{len(samples)} passed, {failed} failed")
    print(f"{'='*70}")

if __name__ == '__main__':
    json_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('output_resume_12241140/filtered/benchmark_cwd.json')
    num_samples = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    check_samples(json_path, num_samples)
