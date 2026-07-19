import os

from pydantic_settings import BaseSettings


class CisaKevParserSettings(BaseSettings):
    FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "cisa_kev"
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 12

    class Config:
        env_file = ".env"


settings = CisaKevParserSettings()