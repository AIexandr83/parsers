import os

from pydantic_settings import BaseSettings


class ParserSettings(BaseSettings):
    REPO_URL: str = "https://github.com/CVEProject/cvelistV5.git"
    REPO_PATH: str = "/app/cvelistV5"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "github_cvelistv5"
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 1

    class Config:
        env_file = ".env"


settings = ParserSettings()
