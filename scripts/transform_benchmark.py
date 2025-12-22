#!/usr/bin/env python3
"""
数据清理与格式转换脚本

功能：
1. 从标准化 CSV 文件读取数据（流式处理）
2. 过滤语言（只保留 c/c++ 和 java）
3. 过滤 Unknown CWE
4. 验证 GitHub commit URLs（使用缓存）
5. 映射 CWE 到 CWD
6. 提取代码结构（context, class, func）
7. 按 (language, CWD) 分组
8. 对超过 --n 个样本的 CWD 进行聚类
9. 输出为新的 JSON 格式

依赖：
    pip install requests scikit-learn numpy
"""

import argparse
import csv
import difflib
import gzip
import json
import logging
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 导入项目模块
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from src.utils.cwe_utils import (
        load_cwd_mapping,
        get_cwd_for_cwe,
        get_all_cwds_for_cwe,
        is_unknown_cwe,
        normalize_cwe
    )
    from src.dataset.common import (
        load_url_cache,
        save_url_cache,
        validate_github_url,
        ensure_https
    )
except ImportError as e:
    logger.error(f"Failed to import project modules: {e}")
    sys.exit(1)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("numpy not available, clustering will be skipped")

try:
    from sklearn.cluster import KMeans
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available, clustering will be skipped")


# ============================================================================
# Language Normalization
# ============================================================================

LANGUAGE_MAPPING = {
    # C/C++ variants
    'c': 'c/c++',
    'C': 'c/c++',
    'cpp': 'c/c++',
    'c++': 'c/c++',
    'C++': 'c/c++',
    'C/C++': 'c/c++',
    'Cpp': 'c/c++',
    'CPP': 'c/c++',
    # Java variants
    'java': 'java',
    'Java': 'java',
    'JAVA': 'java',
}

SUPPORTED_LANGUAGES = {'c/c++', 'java'}


def normalize_language(language: str) -> Optional[str]:
    """
    Normalize language to standard form.

    Args:
        language: Raw language string

    Returns:
        Normalized language ('c/c++' or 'java'), or None if unsupported
    """
    if not language:
        return None

    normalized = LANGUAGE_MAPPING.get(language.strip())
    return normalized if normalized in SUPPORTED_LANGUAGES else None


# ============================================================================
# Code Structure Extraction
# ============================================================================

def extract_c_cpp_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract class and function names from C/C++ code."""
    # Class pattern (struct or class)
    class_pattern = r'(?:struct|class)\s+(\w+)'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # Function pattern
    func_pattern = r'\b(\w+)\s*\([^)]*\)\s*\{'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(1) if func_match else None

    return class_name, func_name


def extract_java_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract class and function names from Java code."""
    # Class pattern
    class_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:class|interface|enum)\s+(\w+)'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # Method pattern
    func_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(1) if func_match else None

    return class_name, func_name


def extract_structure(code: str, language: str) -> Dict[str, Optional[str]]:
    """
    Extract code structure based on language.

    Args:
        code: Source code
        language: Programming language

    Returns:
        Dictionary with 'context', 'class', and 'func' keys
    """
    if not code:
        return {'context': None, 'class': None, 'func': None}

    class_name = None
    func_name = None

    # Extract based on language
    if language == 'c/c++':
        class_name, func_name = extract_c_cpp_structure(code)
    elif language == 'java':
        class_name, func_name = extract_java_structure(code)

    return {
        'context': code if code else None,
        'class': class_name,
        'func': code if func_name else None  # Full function code if function detected
    }


# ============================================================================
# Diff Lines Extraction
# ============================================================================

def extract_diff_lines(
    code_before: str,
    code_after: str,
    context: int = 2
) -> Tuple[List[List[str]], List[List[str]]]:
    """
    Extract diff hunks with context lines.

    Args:
        code_before: Vulnerable code (original)
        code_after: Benign code (fixed)
        context: Number of context lines before and after each hunk

    Returns:
        Tuple of (benign_lines, vulnerable_lines) where each is a list of hunks,
        and each hunk is a list of code lines.
    """
    if not code_before or not code_after:
        return [], []

    lines_before = code_before.splitlines()
    lines_after = code_after.splitlines()

    matcher = difflib.SequenceMatcher(None, lines_before, lines_after)

    benign_hunks = []
    vulnerable_hunks = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            continue

        # Extract vulnerable code hunk (from code_before) with context
        start_v = max(0, i1 - context)
        end_v = min(len(lines_before), i2 + context)
        if end_v > start_v:
            vulnerable_hunks.append(lines_before[start_v:end_v])

        # Extract benign code hunk (from code_after) with context
        start_b = max(0, j1 - context)
        end_b = min(len(lines_after), j2 + context)
        if end_b > start_b:
            benign_hunks.append(lines_after[start_b:end_b])

    return benign_hunks, vulnerable_hunks


# ============================================================================
# CVE Extraction from CVEfixes
# ============================================================================

def extract_commit_hash_from_url(commit_url: str) -> Optional[str]:
    """
    Extract commit hash from GitHub commit URL.

    Args:
        commit_url: GitHub commit URL (e.g., https://github.com/user/repo/commit/abc123)

    Returns:
        Commit hash or None if not found
    """
    if not commit_url:
        return None

    # Pattern: /commit/[hash]
    match = re.search(r'/commit/([0-9a-f]+)', commit_url)
    if match:
        return match.group(1)

    return None


def _split_sql_values(payload: str) -> List[str]:
    """Split the comma-separated value list of an INSERT statement (from cvefixes.py)."""
    values: List[str] = []
    current: List[str] = []
    depth = 0
    in_string = False
    i = 0
    length = len(payload)

    while i < length:
        ch = payload[i]
        if in_string:
            current.append(ch)
            if ch == "'":
                if i + 1 < length and payload[i + 1] == "'":
                    current.append("'")
                    i += 1
                else:
                    in_string = False
            i += 1
            continue

        if ch == "'":
            in_string = True
            current.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            values.append("".join(current).strip())
            current.clear()
            i += 1
            continue
        current.append(ch)
        i += 1

    if current:
        values.append("".join(current).strip())
    return values


def _evaluate_expression(cursor: sqlite3.Cursor, expression: str) -> str:
    """Evaluate SQL expression (from cvefixes.py)."""
    expression = expression.strip()
    if not expression:
        return ""
    lowered = expression.lower()
    if lowered in {"null", "'none'", "'nan'"}:
        return ""
    try:
        cursor.execute(f"SELECT {expression}")
    except sqlite3.OperationalError:
        return ""
    row = cursor.fetchone()
    value = row[0] if row else ""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    else:
        value = str(value)
    if value.lower() in {"none", "nan"}:
        return ""
    return value


def load_cvefixes_cve_mapping(cvefixes_root: Path) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    """
    Load commit hash to CVE ID and description mapping from CVEfixes SQL dump.

    Args:
        cvefixes_root: Root directory containing cvefixes/CVEfixes_v*/Data/*.sql.gz

    Returns:
        Dictionary mapping commit hash to (cve_id, description) tuple
    """
    # Locate SQL dump - check multiple possible locations
    sql_path = None
    possible_dirs = [
        cvefixes_root / "cvefixes",
        cvefixes_root / "datasets" / "cvefixes",
    ]

    for cvefixes_dir in possible_dirs:
        if cvefixes_dir.exists():
            # Look for CVEfixes_v*.*.*/Data/CVEfixes_v*.*.*.sql.gz
            for version_dir in sorted(cvefixes_dir.iterdir(), reverse=True):
                if version_dir.is_dir() and version_dir.name.startswith("CVEfixes_v"):
                    data_dir = version_dir / "Data"
                    if data_dir.exists():
                        for sql_file in data_dir.glob("*.sql.gz"):
                            # Skip hidden files (._*)
                            if not sql_file.name.startswith('._'):
                                sql_path = sql_file
                                break
                    if sql_path:
                        break
            if sql_path:
                break

    if not sql_path or not sql_path.exists():
        logger.warning("CVEfixes SQL dump not found, CVE extraction will be skipped")
        return {}

    logger.info(f"Loading CVE mapping from {sql_path}...")

    # First pass: collect CVE IDs per commit
    commit_to_cves: Dict[str, Set[str]] = defaultdict(set)
    # Second pass: collect CVE descriptions
    cve_descriptions: Dict[str, str] = {}

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    try:
        with gzip.open(sql_path, "rt", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                # Parse fixes table: (cve_id, hash, repo_url)
                if line.startswith("INSERT INTO fixes"):
                    try:
                        values = _split_sql_values(line[line.index("VALUES(") + 7:line.rfind(")")])
                        if len(values) >= 2:
                            cve_id = _evaluate_expression(cursor, values[0])
                            commit_hash = _evaluate_expression(cursor, values[1])
                            if commit_hash and cve_id:
                                commit_to_cves[commit_hash].add(cve_id)
                    except (ValueError, IndexError):
                        continue

                # Parse cve table to get descriptions
                # cve table columns: cve_id, published_date, last_modified_date, description, ...
                # So description is the 4th column (index 3)
                # Description is stored as JSON array: [{"lang": "en", "value": "..."}]
                elif line.startswith("INSERT INTO cve"):
                    try:
                        values = _split_sql_values(line[line.index("VALUES(") + 7:line.rfind(")")])
                        if len(values) >= 4:
                            cve_id = _evaluate_expression(cursor, values[0])
                            # description is the 4th column (index 3)
                            description_raw = _evaluate_expression(cursor, values[3])
                            if cve_id and description_raw:
                                # Try to parse as JSON and extract English description
                                # SQL dump may use single quotes, convert to double quotes for JSON
                                try:
                                    # Replace single quotes with double quotes for JSON parsing
                                    description_json = description_raw.replace("'", '"')
                                    desc_list = json.loads(description_json)
                                    if isinstance(desc_list, list):
                                        for desc in desc_list:
                                            if isinstance(desc, dict) and desc.get('lang') == 'en':
                                                cve_descriptions[cve_id] = desc.get('value', '')
                                                break
                                        else:
                                            # No English description found, use first one
                                            if desc_list and isinstance(desc_list[0], dict):
                                                cve_descriptions[cve_id] = desc_list[0].get('value', '')
                                    else:
                                        cve_descriptions[cve_id] = description_raw
                                except json.JSONDecodeError:
                                    # Not JSON, use as-is
                                    cve_descriptions[cve_id] = description_raw
                    except (ValueError, IndexError):
                        continue
    finally:
        connection.close()

    # Convert to single CVE per commit with description
    commit_to_cve_info: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    for commit, cves in commit_to_cves.items():
        if cves:
            primary_cve = sorted(cves)[0]
            description = cve_descriptions.get(primary_cve)
            commit_to_cve_info[commit] = (primary_cve, description)

    logger.info(f"Loaded CVE mapping for {len(commit_to_cve_info)} commits")
    logger.info(f"Loaded descriptions for {len(cve_descriptions)} CVEs")
    return commit_to_cve_info


# ============================================================================
# CSV Streaming Reader
# ============================================================================

def read_standardized_csvs(
    standardized_dir: Path,
    cwe_to_cwd_mapping: Dict[str, List[str]],
    url_cache: Dict[str, Dict[str, any]],
    commit_to_cve_info: Dict[str, Tuple[Optional[str], Optional[str]]],
    validate_urls: bool = True,
    github_token: Optional[str] = None,
    limit: int = 0
) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    """
    Stream and filter entries from standardized CSV files.

    Args:
        standardized_dir: Directory containing standardized CSV files
        cwe_to_cwd_mapping: CWE to CWD mapping dictionary
        url_cache: URL validation cache
        commit_to_cve_info: Commit hash to (CVE ID, description) mapping (from CVEfixes)
        validate_urls: Whether to validate GitHub URLs
        github_token: GitHub API token for authentication
        limit: Maximum number of entries to yield (0 = unlimited)

    Yields tuples of (language, cwd, entry_dict)
    """
    csv_files = sorted(standardized_dir.glob('*.csv'))

    total_read = 0
    filtered_language = 0
    filtered_cwe = 0
    filtered_url = 0
    yielded = 0

    for csv_file in csv_files:
        dataset_name = csv_file.stem

        # Skip hidden files (starting with ._) and excluded datasets
        if dataset_name.startswith('._') or dataset_name in ('crossvul', 'bigvul'):
            logger.info(f"Skipping excluded dataset: {dataset_name}")
            continue

        logger.info(f"Processing {dataset_name}.csv...")

        with open(csv_file, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)

            for row in reader:
                total_read += 1

                # Extract fields
                cwe_raw = row.get('cwe', '').strip()
                code_before = row.get('code_before', '').strip()
                code_after = row.get('code_after', '').strip()
                commit_url = row.get('commit_url', '').strip()
                language = row.get('language', '').strip()

                # 1. Filter language
                normalized_lang = normalize_language(language)
                if not normalized_lang:
                    filtered_language += 1
                    continue

                # 2. Parse pipe-separated CWEs (e.g., "CWE-79|CWE-89|CWE-20")
                cwe_list = [normalize_cwe(c.strip()) for c in cwe_raw.split('|') if c.strip()]
                # Filter out Unknown CWEs
                cwe_list = [c for c in cwe_list if not is_unknown_cwe(c)]

                if not cwe_list:
                    filtered_cwe += 1
                    continue

                # 3. Separate primary CWE and other CWEs
                normalized_cwe = cwe_list[0]
                other_cwes = cwe_list[1:] if len(cwe_list) > 1 else []

                # 4. Map primary CWE to CWD (can be None)
                cwd = get_cwd_for_cwe(normalized_cwe, cwe_to_cwd_mapping)
                # Note: Don't filter by CWD here - we need all CWE entries for benchmark_cwe.json

                # 5. Map other_CWEs to other_CWDs (exclude primary CWD)
                other_cwds = []
                for other_cwe in other_cwes:
                    other_cwd = get_cwd_for_cwe(other_cwe, cwe_to_cwd_mapping)
                    # Only include if: 1) CWD exists, 2) not same as primary CWD, 3) not already in list
                    if other_cwd and other_cwd != cwd and other_cwd not in other_cwds:
                        other_cwds.append(other_cwd)

                # 6. Validate GitHub URL (if enabled)
                if validate_urls and commit_url:
                    commit_url_https = ensure_https(commit_url)
                    if commit_url_https and not validate_github_url(
                        commit_url_https, url_cache, github_token=github_token
                    ):
                        filtered_url += 1
                        continue
                    commit_url = commit_url_https

                # 7. Extract code structures
                benign_structure = extract_structure(code_after, normalized_lang)
                vulnerable_structure = extract_structure(code_before, normalized_lang)

                # 8. Extract diff lines (hunks with context)
                benign_lines, vulnerable_lines = extract_diff_lines(code_before, code_after)

                # 9. Extract CVE ID and description (if available from CVEfixes)
                cve_id = None
                review_message = None
                if commit_url:
                    commit_hash = extract_commit_hash_from_url(commit_url)
                    if commit_hash:
                        cve_info = commit_to_cve_info.get(commit_hash)
                        if cve_info:
                            cve_id, review_message = cve_info

                # 10. Build entry
                entry = {
                    'benign_code': {
                        'context': benign_structure['context'],
                        'class': benign_structure['class'],
                        'func': benign_structure['func'],
                        'lines': benign_lines
                    },
                    'vulnerable_code': {
                        'context': vulnerable_structure['context'],
                        'class': vulnerable_structure['class'],
                        'func': vulnerable_structure['func'],
                        'lines': vulnerable_lines
                    },
                    'source': dataset_name,
                    'commit_url': commit_url if commit_url else None,
                    'review_message': review_message,
                    'CWE': normalized_cwe,
                    'other_CWEs': other_cwes,
                    'other_CWDs': other_cwds,
                    'CVE': cve_id
                }

                yielded += 1
                yield (normalized_lang, cwd, entry)

                # Check limit
                if limit > 0 and yielded >= limit:
                    logger.info(f"Reached limit of {limit} entries, stopping...")
                    return

                # Log progress periodically
                if total_read % 10000 == 0:
                    logger.info(f"  Processed {total_read} rows, yielded {yielded} entries")

    # Final statistics
    logger.info(f"\n{'='*70}")
    logger.info(f"Filtering Statistics:")
    logger.info(f"  Total read:           {total_read:,}")
    logger.info(f"  Filtered (language):  {filtered_language:,}")
    logger.info(f"  Filtered (CWE):       {filtered_cwe:,}")
    logger.info(f"  Filtered (URL):       {filtered_url:,}")
    logger.info(f"  Final yielded:        {yielded:,}")
    logger.info(f"{'='*70}\n")


# ============================================================================
# Clustering
# ============================================================================

def load_embeddings_from_cache(cwe: str, cache_dir: Path) -> Optional[np.ndarray]:
    """Load cached embeddings for a CWE."""
    cache_file = cache_dir / f"{cwe.replace('/', '_')}.npy"

    if cache_file.exists():
        try:
            embeddings = np.load(cache_file, allow_pickle=False)
            logger.info(f"  Loaded embeddings from cache: {embeddings.shape}")
            return embeddings
        except Exception as e:
            logger.warning(f"  Failed to load embeddings: {e}")

    return None


def cluster_and_select(
    entries: List[Dict[str, Any]],
    n_samples: int,
    cwe: str,
    embeddings_cache_dir: Path
) -> List[Dict[str, Any]]:
    """
    Cluster entries and select n_samples representatives.

    Args:
        entries: List of entries to cluster
        n_samples: Number of samples to select
        cwe: CWE identifier (for loading embeddings)
        embeddings_cache_dir: Directory containing cached embeddings

    Returns:
        List of selected entries
    """
    if not NUMPY_AVAILABLE or not SKLEARN_AVAILABLE:
        logger.warning("  Clustering libraries not available, using random sampling")
        import random
        return random.sample(entries, min(n_samples, len(entries)))

    # Try to load embeddings
    embeddings = load_embeddings_from_cache(cwe, embeddings_cache_dir)

    if embeddings is None or len(embeddings) != len(entries):
        logger.warning(f"  No valid embeddings found for {cwe}, using stratified sampling")
        # Fallback: stratified sampling by source
        from collections import defaultdict
        import random

        by_source = defaultdict(list)
        for i, entry in enumerate(entries):
            by_source[entry['source']].append(i)

        # Calculate samples per source proportionally
        selected_indices = []
        remaining = n_samples

        for source, indices in sorted(by_source.items()):
            proportion = len(indices) / len(entries)
            count = min(remaining, max(1, int(n_samples * proportion)))
            selected_indices.extend(random.sample(indices, min(count, len(indices))))
            remaining -= count

            if remaining <= 0:
                break

        return [entries[i] for i in selected_indices[:n_samples]]

    # Perform clustering
    logger.info(f"  Clustering {len(entries)} entries into {n_samples} clusters...")

    kmeans = KMeans(n_clusters=n_samples, random_state=42, n_init=10)
    labels = kmeans.fit_predict(embeddings)

    # Select closest sample to each cluster center
    selected_entries = []
    for cluster_id in range(n_samples):
        cluster_indices = np.where(labels == cluster_id)[0]

        if len(cluster_indices) == 0:
            continue

        # Find closest point to cluster center
        cluster_embeddings = embeddings[cluster_indices]
        center = kmeans.cluster_centers_[cluster_id]
        distances = np.linalg.norm(cluster_embeddings - center, axis=1)
        closest_idx = cluster_indices[np.argmin(distances)]

        selected_entries.append(entries[closest_idx])

    logger.info(f"  Selected {len(selected_entries)} representative samples")
    return selected_entries


# ============================================================================
# Dual Format Output
# ============================================================================

def write_dual_outputs(
    cwd_data: Dict[str, Dict[str, List[Dict[str, Any]]]],
    cwe_data: Dict[str, Dict[str, List[Dict[str, Any]]]],
    output_dir: Path,
    cwd_filename: str = "benchmark_cwd.json",
    cwe_filename: str = "benchmark_cwe.json"
) -> None:
    """
    Write both CWD-grouped and CWE-grouped output files.

    Args:
        cwd_data: Data grouped by (language, CWD) - only entries with CWD mapping
        cwe_data: Data grouped by (language, CWE) - all entries with valid CWE
        output_dir: Output directory
        cwd_filename: Filename for CWD-grouped output
        cwe_filename: Filename for CWE-grouped output
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # CWD-grouped output: {language: {CWD: [entries]}}
    cwd_path = output_dir / cwd_filename
    logger.info(f"Writing CWD-grouped output to {cwd_path}...")
    with open(cwd_path, 'w', encoding='utf-8') as f:
        json.dump(cwd_data, f, indent=2, ensure_ascii=False)

    # CWE-grouped output: {language: {CWE: [entries]}}
    cwe_path = output_dir / cwe_filename
    logger.info(f"Writing CWE-grouped output to {cwe_path}...")
    with open(cwe_path, 'w', encoding='utf-8') as f:
        json.dump(cwe_data, f, indent=2, ensure_ascii=False)

    logger.info(f"Output files written to {output_dir}")


# ============================================================================
# Main Processing
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Transform standardized CSV data to new JSON format'
    )
    parser.add_argument(
        '--n', '--max-samples',
        type=int,
        default=300,
        help='Maximum samples per CWD (default: 300)'
    )
    parser.add_argument(
        '--standardized-dir',
        type=Path,
        default=Path('clean/standardized'),
        help='Directory containing standardized CSV files'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('.'),
        help='Output directory for benchmark files (default: current directory)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=0,
        help='Limit number of entries to process (0 = unlimited, use 5 for preview)'
    )
    parser.add_argument(
        '--embeddings-cache',
        type=Path,
        default=Path('embeddings_cache'),
        help='Embeddings cache directory'
    )
    parser.add_argument(
        '--collect-json',
        type=Path,
        default=Path('collect.json'),
        help='CWE to CWD mapping file'
    )
    parser.add_argument(
        '--url-cache',
        type=Path,
        default=Path('url_cache.json'),
        help='URL validation cache file'
    )
    parser.add_argument(
        '--skip-url-validation',
        action='store_true',
        help='Skip GitHub URL validation'
    )
    parser.add_argument(
        '--github-token',
        type=str,
        default=None,
        help='GitHub Personal Access Token for API authentication (increases rate limit from 60 to 5000 req/hour)'
    )

    args = parser.parse_args()

    # Try to load GitHub token from environment if not provided
    if not args.github_token:
        import os
        args.github_token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')

    # Validate inputs
    if not args.standardized_dir.exists():
        logger.error(f"Standardized directory not found: {args.standardized_dir}")
        sys.exit(1)

    if not args.collect_json.exists():
        logger.error(f"collect.json not found: {args.collect_json}")
        sys.exit(1)

    # Load CWE to CWD mapping
    logger.info("Loading CWE to CWD mapping...")
    cwe_to_cwd_mapping = load_cwd_mapping(args.collect_json)
    logger.info(f"Loaded {len(cwe_to_cwd_mapping)} CWE to CWD mappings")

    # Load URL cache
    logger.info("Loading URL validation cache...")
    url_cache = load_url_cache(args.url_cache)
    logger.info(f"Loaded {len(url_cache)} cached URL validations")

    # Load CVE mapping from CVEfixes
    logger.info("Loading CVE mapping from CVEfixes...")
    # Use current working directory as root (where cvefixes/ is located)
    commit_to_cve = load_cvefixes_cve_mapping(Path.cwd())
    if commit_to_cve:
        logger.info(f"Loaded CVE mapping for {len(commit_to_cve)} commits")
    else:
        logger.info("CVE mapping not loaded (CVEfixes not available)")

    # Stream and group entries separately for CWD and CWE outputs
    logger.info("Streaming and filtering CSV files...")
    cwd_entries = defaultdict(list)  # (language, cwd) -> entries (only with CWD mapping)
    cwe_entries = defaultdict(list)  # (language, cwe) -> entries (all valid CWE)

    # Log GitHub token status
    if not args.skip_url_validation:
        if args.github_token:
            logger.info("Using GitHub token for authentication (5000 req/hour limit)")
        else:
            logger.warning("No GitHub token provided (60 req/hour limit)")
            logger.warning("Set GITHUB_TOKEN env var or use --github-token for higher limits")

    for language, cwd, entry in read_standardized_csvs(
        args.standardized_dir,
        cwe_to_cwd_mapping,
        url_cache,
        commit_to_cve,
        validate_urls=not args.skip_url_validation,
        github_token=args.github_token,
        limit=args.limit
    ):
        cwe = entry['CWE']
        # All entries go to CWE output
        cwe_entries[(language, cwe)].append(entry)
        # Only entries with CWD mapping go to CWD output
        if cwd:
            cwd_entries[(language, cwd)].append(entry)

    logger.info(f"Grouped into {len(cwd_entries)} (language, CWD) combinations")
    logger.info(f"Grouped into {len(cwe_entries)} (language, CWE) combinations")

    # Save URL cache
    if not args.skip_url_validation:
        logger.info("Saving URL validation cache...")
        save_url_cache(url_cache, args.url_cache)

    # Apply clustering/sampling for large groups (CWD data)
    logger.info("Applying clustering/sampling to CWD groups...")
    final_cwd_data = defaultdict(lambda: defaultdict(list))

    for (language, cwd), entries in sorted(cwd_entries.items()):
        logger.info(f"Processing CWD {language} / {cwd}: {len(entries)} entries")

        if len(entries) > args.n:
            primary_cwe = entries[0]['CWE']
            selected_entries = cluster_and_select(
                entries, args.n, primary_cwe, args.embeddings_cache
            )
        else:
            selected_entries = entries

        final_cwd_data[language][cwd] = selected_entries
        logger.info(f"  Kept {len(selected_entries)} entries")

    # Apply clustering/sampling for large groups (CWE data)
    logger.info("Applying clustering/sampling to CWE groups...")
    final_cwe_data = defaultdict(lambda: defaultdict(list))

    for (language, cwe), entries in sorted(cwe_entries.items()):
        logger.info(f"Processing CWE {language} / {cwe}: {len(entries)} entries")

        if len(entries) > args.n:
            selected_entries = cluster_and_select(
                entries, args.n, cwe, args.embeddings_cache
            )
        else:
            selected_entries = entries

        final_cwe_data[language][cwe] = selected_entries
        logger.info(f"  Kept {len(selected_entries)} entries")

    # Convert defaultdict to regular dict for output
    cwd_output = {lang: dict(cwd_dict) for lang, cwd_dict in final_cwd_data.items()}
    cwe_output = {lang: dict(cwe_dict) for lang, cwe_dict in final_cwe_data.items()}

    # Write dual format outputs
    write_dual_outputs(cwd_output, cwe_output, args.output_dir)

    # Print statistics
    logger.info(f"\n{'='*70}")
    logger.info("Final Statistics (CWD):")

    for language in sorted(cwd_output.keys()):
        lang_data = cwd_output[language]
        total_entries = sum(len(entries) for entries in lang_data.values())
        logger.info(f"\n  Language: {language}")
        logger.info(f"    CWDs: {len(lang_data)}")
        logger.info(f"    Total entries: {total_entries}")

    logger.info(f"\nFinal Statistics (CWE):")

    for language in sorted(cwe_output.keys()):
        lang_data = cwe_output[language]
        total_entries = sum(len(entries) for entries in lang_data.values())
        logger.info(f"\n  Language: {language}")
        logger.info(f"    CWEs: {len(lang_data)}")
        logger.info(f"    Total entries: {total_entries}")

    logger.info(f"{'='*70}")
    logger.info(f"Transformation complete! Output saved to: {args.output_dir}")


if __name__ == '__main__':
    main()
