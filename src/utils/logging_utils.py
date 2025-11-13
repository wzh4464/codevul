"""
Common utilities for logging configuration.

This module provides functions for setting up consistent logging
across all scripts in the project.
"""

import logging
import sys
from pathlib import Path
from typing import Optional, Union


def setup_logging(
    level: Union[int, str] = logging.INFO,
    format_string: Optional[str] = None,
    log_file: Optional[Union[str, Path]] = None,
    console: bool = True,
    name: Optional[str] = None
) -> logging.Logger:
    """
    Set up logging with consistent configuration.

    Args:
        level: Logging level (default: INFO)
        format_string: Custom format string (default: standard format with timestamp)
        log_file: Optional log file path
        console: If True, log to console (default: True)
        name: Logger name (default: root logger)

    Returns:
        Configured logger instance

    Example:
        >>> logger = setup_logging(level='DEBUG', log_file='app.log')
        >>> logger.info("Application started")
    """
    # Convert string level to logging constant
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Default format string
    if format_string is None:
        format_string = '%(asctime)s - %(levelname)s - %(message)s'

    # Create formatter
    formatter = logging.Formatter(format_string)

    # Get or create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance by name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_log_level(
    level: Union[int, str],
    logger: Optional[logging.Logger] = None
) -> None:
    """
    Set logging level for a logger.

    Args:
        level: New logging level
        logger: Logger instance (default: root logger)
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    if logger is None:
        logger = logging.getLogger()

    logger.setLevel(level)

    # Also set level for all handlers
    for handler in logger.handlers:
        handler.setLevel(level)


def add_file_handler(
    log_file: Union[str, Path],
    level: Union[int, str] = logging.INFO,
    format_string: Optional[str] = None,
    logger: Optional[logging.Logger] = None
) -> logging.FileHandler:
    """
    Add a file handler to a logger.

    Args:
        log_file: Path to log file
        level: Logging level for this handler
        format_string: Custom format string (default: standard format)
        logger: Logger instance (default: root logger)

    Returns:
        Created FileHandler instance
    """
    log_file = Path(log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    if format_string is None:
        format_string = '%(asctime)s - %(levelname)s - %(message)s'

    if logger is None:
        logger = logging.getLogger()

    formatter = logging.Formatter(format_string)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return file_handler


def configure_verbose_logging(verbose: bool = False) -> None:
    """
    Configure logging based on verbose flag.

    Args:
        verbose: If True, set DEBUG level; otherwise INFO
    """
    level = logging.DEBUG if verbose else logging.INFO
    set_log_level(level)


# Pre-configured logging formats
FORMAT_SIMPLE = '%(levelname)s - %(message)s'
FORMAT_STANDARD = '%(asctime)s - %(levelname)s - %(message)s'
FORMAT_DETAILED = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
FORMAT_FULL = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'


def setup_script_logging(
    script_name: str,
    verbose: bool = False,
    log_file: Optional[Union[str, Path]] = None
) -> logging.Logger:
    """
    Set up logging for a script with standard configuration.

    This is a convenience function for setting up logging in scripts
    with common defaults.

    Args:
        script_name: Name of the script (typically __name__)
        verbose: If True, use DEBUG level; otherwise INFO
        log_file: Optional log file path

    Returns:
        Configured logger instance

    Example:
        >>> # At the top of your script
        >>> logger = setup_script_logging(__name__, verbose=True)
        >>> logger.info("Script started")
    """
    level = logging.DEBUG if verbose else logging.INFO

    return setup_logging(
        level=level,
        format_string=FORMAT_STANDARD,
        log_file=log_file,
        console=True,
        name=script_name
    )


class LoggerContext:
    """
    Context manager for temporary logging configuration.

    Example:
        >>> with LoggerContext(level='DEBUG'):
        ...     logger.debug("This will be logged")
        >>> # Outside context, returns to previous level
    """

    def __init__(
        self,
        level: Optional[Union[int, str]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize logger context.

        Args:
            level: Temporary logging level
            logger: Logger instance (default: root logger)
        """
        self.logger = logger or logging.getLogger()
        self.new_level = level
        self.old_level = None

    def __enter__(self):
        """Save current level and set new level."""
        self.old_level = self.logger.level

        if self.new_level is not None:
            if isinstance(self.new_level, str):
                self.new_level = getattr(logging, self.new_level.upper(), logging.INFO)
            self.logger.setLevel(self.new_level)

        return self.logger

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore previous logging level."""
        if self.old_level is not None:
            self.logger.setLevel(self.old_level)
