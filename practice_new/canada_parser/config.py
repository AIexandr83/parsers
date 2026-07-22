import os

from pydantic_settings import BaseSettings


class CanadaParserSettings(BaseSettings):
    API_URL: str = "https://www.cyber.gc.ca/api/cccs/threats/v1/get?content_type=cccs_threat&lang=en"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "cyber_gc_ca"
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 12
    STATE_DIR: str = "/app/state"
    STATE_FILE: str = "/app/state/last_run.txt"

    class Config:
        env_file = ".env"


settings = CanadaParserSettings()