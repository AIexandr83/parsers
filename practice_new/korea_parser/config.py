import os

from pydantic_settings import BaseSettings


class KoreaParserSettings(BaseSettings):
    RSS_URL: str = "https://knvd.krcert.or.kr/rss/security/info"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "krcert_kr"
    UPDATE_INTERVAL_HOURS: int = 12
    BATCH_SIZE: int = 100  # фид маленький, но оставляем механику батчей для единообразия

    class Config:
        env_file = ".env"


settings = KoreaParserSettings()