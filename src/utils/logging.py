"""
Logging utilities for the HTTP Request Smuggling Detection Tool.

This module provides logging configuration and helper functions.
"""

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """Set up logging for the application.
    
    Args:
        level: Logging level (e.g., logging.INFO, logging.DEBUG)
        log_file: Optional file path to write logs to
        verbose: Whether to enable verbose logging
        
    Returns:
        Configured logger
    """
    # Create logger
    logger = logging.getLogger('hrs_finder')
    logger.setLevel(logging.DEBUG if verbose else level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler with rich formatting
    console = Console(stderr=True)
    console_handler = RichHandler(
        console=console,
        show_path=True,  # Always show path
        show_time=True,  # Always show time
        markup=True,
        rich_tracebacks=True,
        enable_link_path=True,  # Enable clickable file paths in supported terminals
    )
    console_handler.setLevel(logging.DEBUG if verbose else level)
    
    # Set format to include timestamp, filename, line number
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # We can't directly set formatter on RichHandler, but we can configure the underlying format
    # RichHandler will use this format for non-rich logging
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
    
    return logger


def get_logger() -> logging.Logger:
    """Get the application logger.
    
    Returns:
        Application logger
    """
    return logging.getLogger('hrs_finder')


def log_request(
    logger: logging.Logger,
    method: str,
    path: str,
    headers: list,
    body: Optional[bytes] = None,
    raw: Optional[bytes] = None,
) -> None:
    """Log an HTTP request.
    
    Args:
        logger: Logger to use
        method: HTTP method
        path: Request path
        headers: Request headers
        body: Request body
        raw: Raw request bytes
    """
    if logger.level > logging.DEBUG:
        return
        
    if raw:
        logger.debug("Sending raw request:")
        try:
            logger.debug(raw.decode('utf-8', errors='replace'))
        except Exception:
            logger.debug(f"<Binary data: {len(raw)} bytes>")
        return
        
    logger.debug(f"Sending {method} request to {path}")
    for name, value in headers:
        logger.debug(f"  {name}: {value}")
        
    if body:
        try:
            body_text = body.decode('utf-8', errors='replace')
            if len(body_text) > 1024:
                logger.debug(f"  Body: {body_text[:1024]}... ({len(body)} bytes)")
            else:
                logger.debug(f"  Body: {body_text}")
        except Exception:
            logger.debug(f"  Body: <Binary data: {len(body)} bytes>")


def log_response(
    logger: logging.Logger,
    status_code: int,
    headers: list,
    body: bytes,
    response_time: float,
) -> None:
    """Log an HTTP response.
    
    Args:
        logger: Logger to use
        status_code: Response status code
        headers: Response headers
        body: Response body
        response_time: Response time in seconds
    """
    if logger.level > logging.DEBUG:
        return
        
    logger.debug(f"Received response: {status_code} ({response_time:.6f}s)")
    for name, value in headers:
        logger.debug(f"  {name}: {value}")
        
    try:
        body_text = body.decode('utf-8', errors='replace')
        if len(body_text) > 1024:
            logger.debug(f"  Body: {body_text[:1024]}... ({len(body)} bytes)")
        else:
            logger.debug(f"  Body: {body_text}")
    except Exception:
        logger.debug(f"  Body: <Binary data: {len(body)} bytes>")
