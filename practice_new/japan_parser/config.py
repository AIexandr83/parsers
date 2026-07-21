import os

from pydantic_settings import BaseSettings


class JapanParserSettings(BaseSettings):
    BASE_URL: str = "https://jvndb.jvn.jp/myjvn"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "jvn_jp"
    PAGE_SIZE: int = 50
    REQUEST_DELAY_SECONDS: float = 1.0  # пауза у КАЖДОГО потока между его собственными запросами
    MAX_WORKERS: int = 3  # суммарный темп = MAX_WORKERS / REQUEST_DELAY_SECONDS ≈ 3 запроса/сек
    HIST_START_YEAR: int = 2000
    INCREMENTAL_LOOKBACK_DAYS: int = 3
    UPDATE_INTERVAL_HOURS: int = 12
    BATCH_SIZE: int = 500
    STATE_DIR: str = "/app/state"
    STATE_FILE: str = "/app/state/last_run.txt"

    class Config:
        env_file = ".env"


settings = JapanParserSettings()