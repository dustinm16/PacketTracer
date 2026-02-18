"""Logging configuration for PacketTracer."""

import logging
from pathlib import Path

# Log file location
LOG_FILE = Path(__file__).parent.parent / "packettracer.log"


def setup_logger(name: str = "packettracer", level: int = logging.DEBUG) -> logging.Logger:
    """Set up and return a logger that writes to file (not stdout to avoid Rich conflicts)."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)

    # File handler only - avoid stdout which conflicts with Rich
    file_handler = logging.FileHandler(LOG_FILE, mode='w')
    file_handler.setLevel(level)

    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%H:%M:%S'
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


# Global logger instance
logger = setup_logger()


def log_exception(msg: str = "Exception occurred"):
    """Log an exception with full traceback."""
    logger.exception(msg)
