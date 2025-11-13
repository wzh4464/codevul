"""
Common utilities for file I/O operations.

This module provides functions for safe file reading and writing with
proper encoding handling, CSV streaming, and error handling.
"""

import csv
import sys
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Union


def read_text_safe(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    fallback_encoding: str = 'latin-1',
    errors: str = 'replace'
) -> Optional[str]:
    """
    Safely read text file with encoding fallback.

    Args:
        file_path: Path to the text file
        encoding: Primary encoding to try (default: utf-8)
        fallback_encoding: Fallback encoding if primary fails (default: latin-1)
        errors: Error handling strategy (default: 'replace')

    Returns:
        File content as string, or None if reading fails
    """
    file_path = Path(file_path)

    if not file_path.exists():
        print(f"Warning: File not found: {file_path}", file=sys.stderr)
        return None

    # Try primary encoding
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError:
        # Try fallback encoding
        try:
            with open(file_path, 'r', encoding=fallback_encoding, errors=errors) as f:
                return f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return None


def write_text_safe(
    content: str,
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    create_dirs: bool = True
) -> bool:
    """
    Safely write text to file.

    Args:
        content: Text content to write
        file_path: Path to the output file
        encoding: File encoding (default: utf-8)
        create_dirs: If True, create parent directories if they don't exist

    Returns:
        True if successful, False otherwise
    """
    file_path = Path(file_path)

    try:
        if create_dirs:
            file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error writing to {file_path}: {e}", file=sys.stderr)
        return False


def read_csv_stream(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    delimiter: str = ',',
    skip_header: bool = False,
    verbose: bool = False
) -> Generator[List[str], None, None]:
    """
    Stream-read CSV file row by row.

    Args:
        file_path: Path to the CSV file
        encoding: File encoding (default: utf-8)
        delimiter: CSV delimiter (default: ',')
        skip_header: If True, skip the first row (default: False)
        verbose: If True, print progress messages

    Yields:
        List of string values for each row
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if verbose:
        print(f"Reading CSV file: {file_path}")

    count = 0
    with open(file_path, 'r', encoding=encoding, newline='') as f:
        reader = csv.reader(f, delimiter=delimiter)

        if skip_header:
            next(reader, None)

        for row in reader:
            count += 1
            yield row

            if verbose and count % 10000 == 0:
                print(f"  Processed {count:,} rows...")

    if verbose:
        print(f"Completed: {count:,} rows read")


def read_csv_dict_stream(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    delimiter: str = ',',
    fieldnames: Optional[List[str]] = None,
    verbose: bool = False
) -> Generator[Dict[str, str], None, None]:
    """
    Stream-read CSV file as dictionaries.

    Args:
        file_path: Path to the CSV file
        encoding: File encoding (default: utf-8)
        delimiter: CSV delimiter (default: ',')
        fieldnames: List of field names. If None, read from first row
        verbose: If True, print progress messages

    Yields:
        Dictionary for each row with field names as keys
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if verbose:
        print(f"Reading CSV file: {file_path}")

    count = 0
    with open(file_path, 'r', encoding=encoding, newline='') as f:
        reader = csv.DictReader(f, delimiter=delimiter, fieldnames=fieldnames)

        for row in reader:
            count += 1
            yield row

            if verbose and count % 10000 == 0:
                print(f"  Processed {count:,} rows...")

    if verbose:
        print(f"Completed: {count:,} rows read")


def write_csv_stream(
    rows: Iterable[Union[List[Any], Dict[str, Any]]],
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    delimiter: str = ',',
    fieldnames: Optional[List[str]] = None,
    write_header: bool = True,
    create_dirs: bool = True,
    verbose: bool = False
) -> int:
    """
    Stream-write rows to CSV file.

    Args:
        rows: Iterable of rows (lists or dicts)
        file_path: Path to the output CSV file
        encoding: File encoding (default: utf-8)
        delimiter: CSV delimiter (default: ',')
        fieldnames: List of field names (required for dict rows)
        write_header: If True and rows are dicts, write header row (default: True)
        create_dirs: If True, create parent directories if needed
        verbose: If True, print progress messages

    Returns:
        Number of rows written
    """
    file_path = Path(file_path)

    if create_dirs:
        file_path.parent.mkdir(parents=True, exist_ok=True)

    if verbose:
        print(f"Writing CSV file: {file_path}")

    count = 0
    rows_iter = iter(rows)

    # Peek at first row to determine type
    try:
        first_row = next(rows_iter)
    except StopIteration:
        # No rows to write
        if verbose:
            print("No rows to write")
        return 0

    with open(file_path, 'w', encoding=encoding, newline='') as f:
        if isinstance(first_row, dict):
            # Dict rows - use DictWriter
            if fieldnames is None:
                fieldnames = list(first_row.keys())

            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delimiter)

            if write_header:
                writer.writeheader()

            # Write first row
            writer.writerow(first_row)
            count += 1

            # Write remaining rows
            for row in rows_iter:
                writer.writerow(row)
                count += 1

                if verbose and count % 10000 == 0:
                    print(f"  Written {count:,} rows...")

        else:
            # List rows - use regular writer
            writer = csv.writer(f, delimiter=delimiter)

            # Write first row
            writer.writerow(first_row)
            count += 1

            # Write remaining rows
            for row in rows_iter:
                writer.writerow(row)
                count += 1

                if verbose and count % 10000 == 0:
                    print(f"  Written {count:,} rows...")

    if verbose:
        print(f"Completed: {count:,} rows written")

    return count


def ensure_directory(dir_path: Union[str, Path]) -> Path:
    """
    Ensure directory exists, creating it if necessary.

    Args:
        dir_path: Path to the directory

    Returns:
        Path object for the directory
    """
    dir_path = Path(dir_path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def file_exists(file_path: Union[str, Path]) -> bool:
    """
    Check if file exists.

    Args:
        file_path: Path to check

    Returns:
        True if file exists, False otherwise
    """
    return Path(file_path).exists()


def get_file_size(file_path: Union[str, Path]) -> int:
    """
    Get file size in bytes.

    Args:
        file_path: Path to the file

    Returns:
        File size in bytes, or -1 if file doesn't exist
    """
    file_path = Path(file_path)
    if file_path.exists():
        return file_path.stat().st_size
    return -1


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if size_bytes < 0:
        return "Unknown"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(size_bytes)
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.1f} {units[unit_index]}"
