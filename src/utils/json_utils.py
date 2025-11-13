"""
Common utilities for JSON/JSONL file processing.

This module provides functions for reading and writing JSON and JSONL (JSON Lines) files
with proper error handling and streaming support for large files.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, Optional, Union


def read_jsonl(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    skip_errors: bool = False,
    verbose: bool = False
) -> Generator[Dict[str, Any], None, None]:
    """
    Stream-read JSONL file line by line.

    Args:
        file_path: Path to the JSONL file
        encoding: File encoding (default: utf-8)
        skip_errors: If True, skip lines with JSON decode errors instead of raising
        verbose: If True, print progress messages

    Yields:
        Dictionary objects parsed from each line

    Raises:
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If a line can't be parsed and skip_errors=False
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if verbose:
        print(f"Reading JSONL file: {file_path}")

    line_count = 0
    error_count = 0

    with open(file_path, 'r', encoding=encoding) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
                line_count += 1
                yield obj

                if verbose and line_count % 10000 == 0:
                    print(f"  Processed {line_count:,} lines...")

            except json.JSONDecodeError as e:
                error_count += 1
                if skip_errors:
                    if verbose:
                        print(f"  Warning: Line {line_num} JSON decode error: {e}")
                    continue
                else:
                    raise json.JSONDecodeError(
                        f"Line {line_num}: {e.msg}",
                        e.doc,
                        e.pos
                    )

    if verbose:
        print(f"Completed: {line_count:,} lines read", end="")
        if error_count > 0:
            print(f", {error_count} errors skipped")
        else:
            print()


def write_jsonl(
    data: Iterable[Dict[str, Any]],
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    ensure_ascii: bool = False,
    verbose: bool = False
) -> int:
    """
    Write data to JSONL file, one object per line.

    Args:
        data: Iterable of dictionaries to write
        file_path: Path to the output JSONL file
        encoding: File encoding (default: utf-8)
        ensure_ascii: If True, escape non-ASCII characters (default: False)
        verbose: If True, print progress messages

    Returns:
        Number of objects written
    """
    file_path = Path(file_path)

    if verbose:
        print(f"Writing JSONL file: {file_path}")

    count = 0
    with open(file_path, 'w', encoding=encoding) as f:
        for obj in data:
            f.write(json.dumps(obj, ensure_ascii=ensure_ascii) + '\n')
            count += 1

            if verbose and count % 10000 == 0:
                print(f"  Written {count:,} lines...")

    if verbose:
        print(f"Completed: {count:,} lines written")

    return count


def json_to_jsonl(
    input_file: Union[str, Path],
    output_file: Union[str, Path],
    flatten_nested: bool = True,
    add_metadata: bool = True,
    encoding: str = 'utf-8',
    verbose: bool = False
) -> int:
    """
    Convert nested JSON file to JSONL format.

    This function handles the common pattern of nested JSON like:
    { "language": { "cwe": [ {...}, {...} ] } }

    And flattens it to JSONL with optional metadata fields.

    Args:
        input_file: Path to input JSON file
        output_file: Path to output JSONL file
        flatten_nested: If True, flatten nested structures (default: True)
        add_metadata: If True, add parent keys as metadata fields (default: True)
        encoding: File encoding (default: utf-8)
        verbose: If True, print progress messages

    Returns:
        Number of objects written to JSONL
    """
    input_file = Path(input_file)
    output_file = Path(output_file)

    if verbose:
        print(f"Reading JSON file: {input_file}")

    try:
        with open(input_file, 'r', encoding=encoding) as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    if verbose:
        print("Converting to JSONL format...")

    count = 0
    with open(output_file, 'w', encoding=encoding) as f:
        if flatten_nested and isinstance(data, dict):
            # Handle nested dict structure like { "language": { "cwe": [...] } }
            for key1, value1 in data.items():
                if isinstance(value1, dict):
                    # Second level
                    for key2, value2 in value1.items():
                        if isinstance(value2, list):
                            # Third level - list of items
                            for item in value2:
                                if add_metadata and isinstance(item, dict):
                                    # Add parent keys as metadata
                                    item_with_meta = {
                                        'language': key1,
                                        'cwe': key2,
                                        **item
                                    }
                                    f.write(json.dumps(item_with_meta, ensure_ascii=False) + '\n')
                                else:
                                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
                                count += 1
                        elif isinstance(value2, dict):
                            # Item is a dict
                            if add_metadata:
                                value2 = {'language': key1, 'cwe': key2, **value2}
                            f.write(json.dumps(value2, ensure_ascii=False) + '\n')
                            count += 1
                else:
                    # Not nested, just write it
                    if add_metadata and isinstance(value1, dict):
                        value1 = {key1: value1}
                    f.write(json.dumps(value1, ensure_ascii=False) + '\n')
                    count += 1

                if verbose and count % 10000 == 0:
                    print(f"  Processed {count:,} records...")

        elif isinstance(data, list):
            # Handle list of objects
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
                count += 1

                if verbose and count % 10000 == 0:
                    print(f"  Processed {count:,} records...")

        else:
            # Single object
            f.write(json.dumps(data, ensure_ascii=False) + '\n')
            count = 1

    if verbose:
        print(f"Conversion complete! {count:,} records written")
        print(f"Output file: {output_file}")

    return count


def load_json_safe(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    default: Optional[Any] = None
) -> Any:
    """
    Safely load JSON file with error handling.

    Args:
        file_path: Path to the JSON file
        encoding: File encoding (default: utf-8)
        default: Default value to return if loading fails (default: None)

    Returns:
        Parsed JSON data or default value on error
    """
    file_path = Path(file_path)

    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: File not found: {file_path}", file=sys.stderr)
        return default
    except json.JSONDecodeError as e:
        print(f"Warning: JSON decode error in {file_path}: {e}", file=sys.stderr)
        return default
    except Exception as e:
        print(f"Warning: Error loading {file_path}: {e}", file=sys.stderr)
        return default


def save_json_safe(
    data: Any,
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    indent: Optional[int] = 2,
    ensure_ascii: bool = False
) -> bool:
    """
    Safely save data to JSON file.

    Args:
        data: Data to save
        file_path: Path to the output JSON file
        encoding: File encoding (default: utf-8)
        indent: Indentation level (default: 2, None for compact)
        ensure_ascii: If True, escape non-ASCII characters (default: False)

    Returns:
        True if successful, False otherwise
    """
    file_path = Path(file_path)

    try:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'w', encoding=encoding) as f:
            json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
        return True
    except Exception as e:
        print(f"Error saving to {file_path}: {e}", file=sys.stderr)
        return False
