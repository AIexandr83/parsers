import os

from pydantic_settings import BaseSettings


class GermanyParserSettings(BaseSettings):
    BASE_URL: str = "https://wid.cert-bund.de/.well-known/csaf/white"
    CHANGES_URL: str = "https://wid.cert-bund.de/.well-known/csaf/white/changes.csv"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "cert_bund_de"
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 12
    STATE_DIR: str = "/app/state"
    STATE_FILE: str = "/app/state/last_run.txt"

    class Config:
        env_file = ".env"


settings = GermanyParserSettings()