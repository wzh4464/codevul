"""
Common utilities for command-line interface (CLI) argument parsing.

This module provides functions for adding common arguments to argparse
parsers and parsing standard command-line options.
"""

import argparse
import sys
from pathlib import Path
from typing import Any, List, Optional, Union


def add_common_args(
    parser: argparse.ArgumentParser,
    include_verbose: bool = True,
    include_output: bool = False,
    include_input: bool = False
) -> argparse.ArgumentParser:
    """
    Add common command-line arguments to an ArgumentParser.

    Args:
        parser: ArgumentParser instance
        include_verbose: If True, add --verbose flag (default: True)
        include_output: If True, add --output argument (default: False)
        include_input: If True, add input file argument (default: False)

    Returns:
        Modified ArgumentParser instance

    Example:
        >>> parser = argparse.ArgumentParser(description='My script')
        >>> parser = add_common_args(parser, include_verbose=True, include_output=True)
        >>> args = parser.parse_args()
    """
    if include_verbose:
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    if include_input:
        parser.add_argument(
            'input',
            type=str,
            help='Input file path'
        )

    if include_output:
        parser.add_argument(
            '-o', '--output',
            type=str,
            help='Output file path'
        )

    return parser


def add_io_args(
    parser: argparse.ArgumentParser,
    input_required: bool = True,
    output_required: bool = False,
    input_help: str = 'Input file path',
    output_help: str = 'Output file path'
) -> argparse.ArgumentParser:
    """
    Add input and output file arguments.

    Args:
        parser: ArgumentParser instance
        input_required: If True, input is required (default: True)
        output_required: If True, output is required (default: False)
        input_help: Help text for input argument
        output_help: Help text for output argument

    Returns:
        Modified ArgumentParser instance
    """
    if input_required:
        parser.add_argument(
            'input',
            type=str,
            help=input_help
        )
    else:
        parser.add_argument(
            '-i', '--input',
            type=str,
            help=input_help
        )

    if output_required:
        parser.add_argument(
            'output',
            type=str,
            help=output_help
        )
    else:
        parser.add_argument(
            '-o', '--output',
            type=str,
            help=output_help
        )

    return parser


def add_encoding_arg(
    parser: argparse.ArgumentParser,
    default: str = 'utf-8'
) -> argparse.ArgumentParser:
    """
    Add encoding argument.

    Args:
        parser: ArgumentParser instance
        default: Default encoding (default: 'utf-8')

    Returns:
        Modified ArgumentParser instance
    """
    parser.add_argument(
        '--encoding',
        type=str,
        default=default,
        help=f'File encoding (default: {default})'
    )

    return parser


def add_limit_args(
    parser: argparse.ArgumentParser,
    default_limit: Optional[int] = None
) -> argparse.ArgumentParser:
    """
    Add limit and offset arguments for pagination.

    Args:
        parser: ArgumentParser instance
        default_limit: Default limit value (default: None = unlimited)

    Returns:
        Modified ArgumentParser instance
    """
    parser.add_argument(
        '--limit',
        type=int,
        default=default_limit,
        help='Maximum number of items to process'
    )

    parser.add_argument(
        '--offset',
        type=int,
        default=0,
        help='Number of items to skip (default: 0)'
    )

    return parser


def parse_path_arg(
    path: Union[str, Path],
    must_exist: bool = True,
    must_be_file: bool = False,
    must_be_dir: bool = False,
    create_dirs: bool = False
) -> Path:
    """
    Parse and validate a path argument.

    Args:
        path: Path string or Path object
        must_exist: If True, path must exist (default: True)
        must_be_file: If True, path must be a file (default: False)
        must_be_dir: If True, path must be a directory (default: False)
        create_dirs: If True, create parent directories for output files (default: False)

    Returns:
        Path object

    Raises:
        argparse.ArgumentTypeError: If validation fails
    """
    path = Path(path)

    if must_exist and not path.exists():
        raise argparse.ArgumentTypeError(f"Path does not exist: {path}")

    if must_be_file and path.exists() and not path.is_file():
        raise argparse.ArgumentTypeError(f"Path is not a file: {path}")

    if must_be_dir and path.exists() and not path.is_dir():
        raise argparse.ArgumentTypeError(f"Path is not a directory: {path}")

    if create_dirs and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    return path


def validate_file_exists(path: str) -> Path:
    """
    Argparse type validator for existing files.

    Args:
        path: Path string

    Returns:
        Path object

    Raises:
        argparse.ArgumentTypeError: If file doesn't exist
    """
    return parse_path_arg(path, must_exist=True, must_be_file=True)


def validate_dir_exists(path: str) -> Path:
    """
    Argparse type validator for existing directories.

    Args:
        path: Path string

    Returns:
        Path object

    Raises:
        argparse.ArgumentTypeError: If directory doesn't exist
    """
    return parse_path_arg(path, must_exist=True, must_be_dir=True)


def create_argument_parser(
    description: str,
    epilog: Optional[str] = None,
    add_help: bool = True
) -> argparse.ArgumentParser:
    """
    Create a standard ArgumentParser with common formatting.

    Args:
        description: Program description
        epilog: Text to display after argument help (default: None)
        add_help: If True, add -h/--help option (default: True)

    Returns:
        ArgumentParser instance
    """
    return argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        add_help=add_help,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )


def parse_key_value_pairs(
    args: List[str],
    separator: str = '='
) -> dict:
    """
    Parse key=value pairs from command line arguments.

    Args:
        args: List of strings in format "key=value"
        separator: Key-value separator (default: '=')

    Returns:
        Dictionary of key-value pairs

    Example:
        >>> parse_key_value_pairs(['foo=bar', 'baz=qux'])
        {'foo': 'bar', 'baz': 'qux'}
    """
    result = {}

    for arg in args:
        if separator not in arg:
            print(f"Warning: Ignoring invalid key-value pair: {arg}", file=sys.stderr)
            continue

        key, value = arg.split(separator, 1)
        result[key.strip()] = value.strip()

    return result


def positive_int(value: str) -> int:
    """
    Argparse type validator for positive integers.

    Args:
        value: String value to parse

    Returns:
        Positive integer value

    Raises:
        argparse.ArgumentTypeError: If value is not a positive integer
    """
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise ValueError()
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a positive integer")


def non_negative_int(value: str) -> int:
    """
    Argparse type validator for non-negative integers.

    Args:
        value: String value to parse

    Returns:
        Non-negative integer value

    Raises:
        argparse.ArgumentTypeError: If value is not a non-negative integer
    """
    try:
        ivalue = int(value)
        if ivalue < 0:
            raise ValueError()
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a non-negative integer")


def bounded_float(minimum: float, maximum: float):
    """
    Create an argparse type validator for floats within a range.

    Args:
        minimum: Minimum allowed value (inclusive)
        maximum: Maximum allowed value (inclusive)

    Returns:
        Validator function

    Example:
        >>> parser.add_argument('--threshold', type=bounded_float(0.0, 1.0))
    """
    def validator(value: str) -> float:
        try:
            fvalue = float(value)
            if not minimum <= fvalue <= maximum:
                raise ValueError()
            return fvalue
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"{value} is not a float between {minimum} and {maximum}"
            )

    return validator


def add_filter_args(
    parser: argparse.ArgumentParser,
    entity_name: str = 'items'
) -> argparse.ArgumentParser:
    """
    Add common filtering arguments.

    Args:
        parser: ArgumentParser instance
        entity_name: Name of entities being filtered (for help text)

    Returns:
        Modified ArgumentParser instance
    """
    parser.add_argument(
        '--filter',
        type=str,
        action='append',
        help=f'Filter {entity_name} (can be used multiple times)'
    )

    parser.add_argument(
        '--exclude',
        type=str,
        action='append',
        help=f'Exclude {entity_name} (can be used multiple times)'
    )

    return parser
