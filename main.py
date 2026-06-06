# main.py
# Entry point — run this to verify everything is set up correctly

import os
import sys

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import settings
from src.utils.logger import setup_logger

logger = setup_logger("main")

def main():
    logger.info("=" * 50)
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    logger.info(f"Data directory: {settings.DATA_DIR}")
    logger.info(f"Models directory: {settings.MODELS_DIR}")
    logger.info(f"Logs directory: {settings.LOGS_DIR}")
    logger.info("=" * 50)

    # Create all required directories
    dirs_to_create = [
        settings.DATA_DIR,
        settings.MODELS_DIR,
        settings.LOGS_DIR,
        os.path.join(settings.DATA_DIR, "raw"),
        os.path.join(settings.DATA_DIR, "processed"),
        os.path.join(settings.DATA_DIR, "attacks"),
    ]

    for directory in dirs_to_create:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"✅ Directory ready: {directory}")

    logger.info("")
    logger.info("🚀 AIOps Platform initialized successfully!")
    logger.info("All systems ready. Proceeding to data simulation...")

if __name__ == "__main__":
    main()