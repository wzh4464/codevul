"""Shared helpers for dataset normalization."""

from __future__ import annotations

import csv
import json
import logging
import re
import sys
import time
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

SCHEMA: List[str] = ["cwe", "code_before", "code_after", "commit_url", "language"]
CWE_PATTERN = re.compile(r"(?i)cwe[-_\\s]*(\\d+)")
csv.field_size_limit(sys.maxsize)


def normalize_cwe(value: object) -> str:
    """Convert a raw CWE reference into the canonical 'CWE-<num>' form."""
    if value is None:
        return ""
    if isinstance(value, int):
        return f"CWE-{value}"

    text = str(value).strip()
    if not text:
        return ""

    match = CWE_PATTERN.search(text)
    if match:
        return f"CWE-{int(match.group(1))}"

    return text


def ensure_https(url: Optional[str]) -> str:
    """Ensure URLs include a scheme and trim whitespace."""
    if not url:
        return ""
    url = url.strip()
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    return "https://" + url.lstrip("/")


def guess_language_from_filename(name: Optional[str]) -> str:
    """Best-effort language guess based on file extension."""
    if not name or name in {"None", "null"}:
        return ""
    suffix = Path(name).suffix.lower().lstrip(".")
    if not suffix:
        return ""
    mapping = {
        "c": "c",
        "h": "c",
        "cc": "cpp",
        "cpp": "cpp",
        "cxx": "cpp",
        "hpp": "cpp",
        "hxx": "cpp",
        "java": "java",
        "py": "python",
        "cs": "csharp",
        "js": "javascript",
        "ts": "typescript",
        "rb": "ruby",
        "php": "php",
        "jsp": "jsp",
        "go": "go",
        "rs": "rust",
        "swift": "swift",
        "kt": "kotlin",
        "m": "objective-c",
        "mm": "objective-cpp",
        "scala": "scala",
        "vb": "vb",
        "pl": "perl",
        "lua": "lua",
        "sh": "shell",
    }
    return mapping.get(suffix, suffix)


def read_text_with_fallback(path: Path) -> str:
    """Read a text file using UTF-8 with a latin-1 fallback."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def write_rows(
    path: Path,
    rows: Iterable[Sequence[str]],
    *,
    limit: Optional[int] = None,
) -> Tuple[int, bool]:
    """Write rows to a CSV file and return (row_count, truncated?)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    truncated = False
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(SCHEMA)
        for row in rows:
            writer.writerow(row)
            count += 1
            if limit is not None and count >= limit:
                truncated = True
                break
    return count, truncated


def iter_json_array(path: Path, chunk_size: int = 1_048_576) -> Iterator[dict]:
    """Stream JSON objects from a large array without loading the whole file."""
    decoder = json.JSONDecoder()
    buffer = ""
    in_array = False

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buffer += chunk

            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break

                if not in_array:
                    if buffer.startswith("["):
                        in_array = True
                        buffer = buffer[1:]
                        continue
                    raise ValueError(f"{path} must start with a JSON array.")

                if buffer.startswith("]"):
                    return

                try:
                    obj, offset = decoder.raw_decode(buffer)
                except JSONDecodeError:
                    break

                yield obj
                buffer = buffer[offset:].lstrip()
                if buffer.startswith(","):
                    buffer = buffer[1:]

        buffer = buffer.lstrip()
        if in_array and buffer.startswith("]"):
            return
        if buffer:
            raise ValueError(f"Unexpected trailing data in {path}: {buffer[:80]!r}")


# ============================================================================
# GitHub URL Validation with Caching
# ============================================================================

def parse_github_url(url: str) -> Optional[Tuple[str, str]]:
    """
    Parse GitHub commit URL and extract username and repository name.

    Args:
        url: GitHub commit URL (e.g., "https://github.com/user/repo/commit/...")

    Returns:
        Tuple of (username, repo_name), or None if not a valid GitHub URL

    Examples:
        >>> parse_github_url("https://github.com/karelzak/util-linux/commit/abc123")
        ("karelzak", "util-linux")
        >>> parse_github_url("https://github.com/user/repo/pull/123")
        ("user", "repo")
    """
    if not url:
        return None

    # Pattern to match GitHub URLs
    # Matches: https://github.com/{username}/{repo}/...
    pattern = r"github\.com/([^/]+)/([^/]+)"
    match = re.search(pattern, url)

    if match:
        username = match.group(1)
        repo_name = match.group(2)
        return (username, repo_name)

    return None


def load_url_cache(cache_path: Path) -> Dict[str, Dict[str, any]]:
    """
    Load URL validation cache from JSON file.

    Args:
        cache_path: Path to cache file

    Returns:
        Dictionary mapping "{username}/{repo}" to validation result
    """
    if not cache_path.exists():
        return {}

    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load URL cache from {cache_path}: {e}")
        return {}


def save_url_cache(cache: Dict[str, Dict[str, any]], cache_path: Path) -> None:
    """
    Save URL validation cache to JSON file.

    Args:
        cache: Dictionary mapping "{username}/{repo}" to validation result
        cache_path: Path to cache file
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        logger.warning(f"Failed to save URL cache to {cache_path}: {e}")


def validate_github_url(
    url: str,
    cache: Dict[str, Dict[str, any]],
    timeout: int = 10,
    delay: float = 0.1,
    github_token: Optional[str] = None
) -> bool:
    """
    Validate if a GitHub commit URL points to a valid, accessible repository.

    Uses caching by repository (username/repo) to avoid repeated validation
    of different commits from the same repository.

    Args:
        url: GitHub commit URL to validate
        cache: URL validation cache (will be updated)
        timeout: Request timeout in seconds (default: 10)
        delay: Delay between requests in seconds to avoid rate limiting (default: 0.1)
        github_token: Optional GitHub Personal Access Token for higher rate limits
                     (default: None, uses unauthenticated API with 60 req/hour limit)
                     With token: 5000 req/hour limit

    Returns:
        True if the repository is valid and accessible, False otherwise

    Note:
        This function requires the 'requests' library to be installed.
        GitHub API rate limits:
        - Without token: 60 requests/hour per IP
        - With token: 5000 requests/hour

        To create a token: https://github.com/settings/tokens
        Required scopes: none (public repo access only)
    """
    parsed = parse_github_url(url)
    if not parsed:
        return False

    username, repo_name = parsed
    cache_key = f"{username}/{repo_name}"

    # Check cache first
    if cache_key in cache:
        return cache[cache_key].get('valid', False)

    # Validate the repository by checking if it exists
    try:
        import requests

        # Use GitHub API to check if repository exists
        # This is more reliable than checking a specific commit URL
        api_url = f"https://api.github.com/repos/{username}/{repo_name}"

        # Prepare headers with optional authentication
        headers = {}
        if github_token:
            headers['Authorization'] = f'token {github_token}'

        # Add a small delay to avoid rate limiting
        time.sleep(delay)

        response = requests.head(api_url, headers=headers, timeout=timeout, allow_redirects=True)

        # Consider 200 and 301/302 (redirects) as valid
        # 403 might be rate limiting, 404 is definitely invalid
        is_valid = response.status_code in (200, 301, 302)

        # Log rate limit info if available
        if 'X-RateLimit-Remaining' in response.headers:
            remaining = response.headers.get('X-RateLimit-Remaining')
            if int(remaining) < 10:
                logger.warning(f"GitHub API rate limit low: {remaining} requests remaining")

        # Cache the result
        cache[cache_key] = {
            'valid': is_valid,
            'checked_at': time.time(),
            'status_code': response.status_code
        }

        return is_valid

    except requests.RequestException as e:
        logger.debug(f"Failed to validate GitHub URL {url}: {e}")
        # On network errors, assume invalid but don't cache
        # (might be temporary network issue)
        return False
    except ImportError:
        logger.warning("requests library not available, skipping URL validation")
        # If requests is not available, assume valid
        return True
