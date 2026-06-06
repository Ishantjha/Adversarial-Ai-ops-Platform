# src/utils/logger.py
# Central logger — every module uses this for consistent logging

import logging
import os
from datetime import datetime
from config.settings import settings

def setup_logger(name: str) -> logging.Logger:
    """
    Creates and returns a logger with both file and console output.
    name: usually the module name e.g. 'detector', 'attacker'
    """

    # Create logs directory if it doesn't exist
    os.makedirs(settings.LOGS_DIR, exist_ok=True)

    # Log file named by date so each day gets its own file
    log_filename = os.path.join(
        settings.LOGS_DIR,
        f"{name}_{datetime.now().strftime('%Y%m%d')}.log"
    )

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, settings.LOG_LEVEL))

    # Avoid duplicate handlers if logger already exists
    if logger.handlers:
        return logger

    # Format: timestamp | level | module | message
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler — shows logs in terminal
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler — saves logs to file
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger