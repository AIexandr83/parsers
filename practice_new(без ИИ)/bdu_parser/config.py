import os

from pydantic_settings import BaseSettings


class BduParserSettings(BaseSettings):
    VULXML_URL: str = "https://bdu.fstec.ru/files/documents/vulxml.zip"
    DOWNLOAD_PATH: str = "/app/data/vulxml.zip"
    EXTRACT_PATH: str = "/app/data/export"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "fstec_bdu"
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 12  # ФСТЭК обновляет архив не каждый час

    class Config:
        env_file = ".env"


settings = BduParserSettings()