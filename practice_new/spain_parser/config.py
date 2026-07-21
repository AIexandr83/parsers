import os

from pydantic_settings import BaseSettings


class SpainParserSettings(BaseSettings):
    BASE_URL: str = "https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "incibe_es"
    REQUEST_DELAY_SECONDS: float = 0.5
    MAX_WORKERS: int = 3
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 12
    STATE_DIR: str = "/app/state"
    STATE_FILE: str = "/app/state/last_run.txt"

    class Config:
        env_file = ".env"


settings = SpainParserSettings()