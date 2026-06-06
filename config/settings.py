# config/settings.py
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "AIOps-Platform")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    DEBUG: bool = os.getenv("DEBUG", "True") == "True"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    BASE_DIR: str = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    DATA_DIR: str = os.path.join(
        BASE_DIR, os.getenv("DATA_DIR", "data")
    )
    MODELS_DIR: str = os.path.join(
        BASE_DIR, os.getenv("MODELS_DIR", "models")
    )
    LOGS_DIR: str = os.path.join(
        BASE_DIR, os.getenv("LOGS_DIR", "logs")
    )

    ALERT_THRESHOLD: float = float(
        os.getenv("ALERT_THRESHOLD", "0.75")
    )
    RETRAIN_TRIGGER_COUNT: int = int(
        os.getenv("RETRAIN_TRIGGER_COUNT", "50")
    )

    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    FEATURE_COLUMNS = [
        "cpu_usage", "memory_usage", "network_in", "network_out",
        "disk_read", "disk_write", "request_rate", "error_rate",
        "response_time", "active_connections"
    ]

    ATTACK_TYPES = [
        "normal", "fgsm_attack", "data_poisoning",
        "log_injection", "model_evasion", "dos_attack"
    ]

settings = Settings()