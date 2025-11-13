"""
Common utility modules for the codevul project.

This package provides reusable utilities for:
- JSON/JSONL file processing (json_utils)
- File I/O operations (file_utils)
- CWE processing and analysis (cwe_utils)
- Benchmark data processing (benchmark_utils)
- Logging configuration (logging_utils)
- CLI argument parsing (cli_utils)
"""

# Version info
__version__ = '1.0.0'

# Import commonly used functions for convenience
from .json_utils import (
    read_jsonl,
    write_jsonl,
    json_to_jsonl,
    load_json_safe,
    save_json_safe
)

from .file_utils import (
    read_text_safe,
    write_text_safe,
    read_csv_stream,
    read_csv_dict_stream,
    write_csv_stream,
    ensure_directory,
    file_exists,
    get_file_size,
    format_file_size
)

from .cwe_utils import (
    normalize_cwe,
    extract_cwe_number,
    is_valid_cwe,
    group_by_cwe,
    count_cwes,
    get_cwe_statistics,
    format_cwe_statistics
)

from .benchmark_utils import (
    calculate_sample_score,
    select_diverse_samples,
    load_benchmark_json,
    filter_benchmark,
    print_benchmark_statistics,
    save_benchmark,
    get_benchmark_summary
)

from .logging_utils import (
    setup_logging,
    setup_script_logging,
    get_logger,
    set_log_level,
    configure_verbose_logging
)

from .cli_utils import (
    add_common_args,
    add_io_args,
    create_argument_parser,
    parse_path_arg,
    validate_file_exists,
    validate_dir_exists,
    positive_int,
    non_negative_int
)

__all__ = [
    # json_utils
    'read_jsonl',
    'write_jsonl',
    'json_to_jsonl',
    'load_json_safe',
    'save_json_safe',
    # file_utils
    'read_text_safe',
    'write_text_safe',
    'read_csv_stream',
    'read_csv_dict_stream',
    'write_csv_stream',
    'ensure_directory',
    'file_exists',
    'get_file_size',
    'format_file_size',
    # cwe_utils
    'normalize_cwe',
    'extract_cwe_number',
    'is_valid_cwe',
    'group_by_cwe',
    'count_cwes',
    'get_cwe_statistics',
    'format_cwe_statistics',
    # benchmark_utils
    'calculate_sample_score',
    'select_diverse_samples',
    'load_benchmark_json',
    'filter_benchmark',
    'print_benchmark_statistics',
    'save_benchmark',
    'get_benchmark_summary',
    # logging_utils
    'setup_logging',
    'setup_script_logging',
    'get_logger',
    'set_log_level',
    'configure_verbose_logging',
    # cli_utils
    'add_common_args',
    'add_io_args',
    'create_argument_parser',
    'parse_path_arg',
    'validate_file_exists',
    'validate_dir_exists',
    'positive_int',
    'non_negative_int',
]
