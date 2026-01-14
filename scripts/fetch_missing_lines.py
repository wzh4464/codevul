#!/usr/bin/env python3
"""Fetch missing lines from GitHub commits."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional, Tuple, List
from dotenv import load_dotenv
import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load .env
load_dotenv()


def parse_commit_url(url: str) -> Optional[Tuple[str, str, str]]:
    """Parse GitHub commit URL to extract owner, repo, commit hash."""
    match = re.match(r'https://github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)', url)
    if match:
        return match.group(1), match.group(2), match.group(3)
    return None


def fetch_commit_diff(owner: str, repo: str, commit: str, token: str, func_code: str) -> List[List[str]]:
    """
    Fetch commit diff from GitHub API and extract lines related to func_code.

    Returns list of line groups (hunks) that match the function.
    """
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3.diff'
    }

    url = f'https://api.github.com/repos/{owner}/{repo}/commits/{commit}'

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 403:
            logger.warning("Rate limited, waiting 60s...")
            time.sleep(60)
            resp = requests.get(url, headers=headers, timeout=30)

        if resp.status_code != 200:
            logger.debug(f"Failed to fetch {owner}/{repo}/{commit}: {resp.status_code}")
            return []

        diff_text = resp.text
        return extract_lines_from_diff(diff_text, func_code)

    except Exception as e:
        logger.debug(f"Error fetching {owner}/{repo}/{commit}: {e}")
        return []


def extract_lines_from_diff(diff_text: str, func_code: Optional[str]) -> List[List[str]]:
    """Extract changed lines from diff that relate to the function code."""
    if not func_code:
        return []

    # Get first line of function to identify it
    func_lines = func_code.strip().split('\n')
    if not func_lines:
        return []

    func_signature = func_lines[0].strip()

    lines_groups = []
    current_hunk = []
    in_relevant_file = False

    for line in diff_text.split('\n'):
        # New file
        if line.startswith('diff --git'):
            if current_hunk:
                lines_groups.append(current_hunk)
                current_hunk = []
            in_relevant_file = False

        # Check if this file contains our function
        elif line.startswith('@@'):
            if current_hunk:
                lines_groups.append(current_hunk)
                current_hunk = []

        # Collect changed lines (+ or -)
        elif line.startswith('+') and not line.startswith('+++'):
            content = line[1:]
            # Check if this relates to our function
            if func_signature in content or any(fl.strip() in content for fl in func_lines[:3] if fl.strip()):
                in_relevant_file = True
            if in_relevant_file:
                current_hunk.append(content)
        elif line.startswith('-') and not line.startswith('---'):
            content = line[1:]
            if func_signature in content or any(fl.strip() in content for fl in func_lines[:3] if fl.strip()):
                in_relevant_file = True
            if in_relevant_file:
                current_hunk.append(content)

    if current_hunk:
        lines_groups.append(current_hunk)

    # Filter empty groups
    return [g for g in lines_groups if g]


def process_benchmark_file(input_path: Path, output_path: Path, token: str) -> dict:
    """Process benchmark file and fetch missing lines."""
    logger.info(f"Loading {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = {'total': 0, 'missing_lines': 0, 'fetched': 0, 'failed': 0, 'no_url': 0}

    for lang, cwd_dict in data.items():
        for cwd_id, entries in cwd_dict.items():
            for entry in entries:
                stats['total'] += 1

                benign_lines = entry.get('benign_code', {}).get('lines', [])
                vuln_lines = entry.get('vulnerable_code', {}).get('lines', [])

                if benign_lines or vuln_lines:
                    continue

                stats['missing_lines'] += 1

                url = entry.get('commit_url', '')
                if not url or 'github.com' not in url:
                    stats['no_url'] += 1
                    continue

                parsed = parse_commit_url(url)
                if not parsed:
                    stats['no_url'] += 1
                    continue

                owner, repo, commit = parsed

                # Fetch lines for vulnerable code
                vuln_func = entry.get('vulnerable_code', {}).get('func')
                if vuln_func:
                    lines = fetch_commit_diff(owner, repo, commit, token, vuln_func)
                    if lines:
                        entry['vulnerable_code']['lines'] = lines

                # Fetch lines for benign code
                benign_func = entry.get('benign_code', {}).get('func')
                if benign_func:
                    lines = fetch_commit_diff(owner, repo, commit, token, benign_func)
                    if lines:
                        entry['benign_code']['lines'] = lines

                # Check if we got any lines
                new_benign = entry.get('benign_code', {}).get('lines', [])
                new_vuln = entry.get('vulnerable_code', {}).get('lines', [])

                if new_benign or new_vuln:
                    stats['fetched'] += 1
                else:
                    stats['failed'] += 1

                # Rate limiting
                time.sleep(0.5)

                if stats['missing_lines'] % 50 == 0:
                    logger.info(f"Progress: {stats['missing_lines']} processed, {stats['fetched']} fetched")

    logger.info(f"Writing to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return stats


def main():
    parser = argparse.ArgumentParser(description='Fetch missing lines from GitHub')
    parser.add_argument('input_dir', type=Path, help='Directory containing benchmark JSON files')
    parser.add_argument('--output-dir', type=Path, help='Output directory (default: input_dir)')
    args = parser.parse_args()

    token = os.getenv('GITHUB_TOKEN') or os.getenv('GITHUB_API_TOKEN')
    if not token:
        logger.error("GITHUB_TOKEN not found in environment or .env file")
        sys.exit(1)

    input_dir = args.input_dir
    output_dir = args.output_dir or input_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    benchmark_files = list(input_dir.glob('benchmark_*.json'))
    if not benchmark_files:
        logger.error(f"No benchmark_*.json files found in {input_dir}")
        sys.exit(1)

    logger.info(f"Found {len(benchmark_files)} benchmark files")
    logger.info(f"Using GitHub token: {token[:8]}...")

    for input_file in benchmark_files:
        output_file = output_dir / input_file.name
        logger.info(f"\nProcessing {input_file.name}...")

        stats = process_benchmark_file(input_file, output_file, token)

        logger.info(f"  Total: {stats['total']}")
        logger.info(f"  Missing lines: {stats['missing_lines']}")
        logger.info(f"  Fetched: {stats['fetched']}")
        logger.info(f"  Failed: {stats['failed']}")
        logger.info(f"  No URL: {stats['no_url']}")


if __name__ == '__main__':
    main()
