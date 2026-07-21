import os

from pydantic_settings import BaseSettings


class PocGithubParserSettings(BaseSettings):
    REPO_URL: str = "https://github.com/nomi-sec/PoC-in-GitHub.git"
    REPO_PATH: str = "/app/poc_repo"
    DB_API_URL: str = os.getenv("DB_API_URL", "http://db_api:8000")
    SOURCE_NAME: str = "poc_github"
    BATCH_SIZE: int = 500
    UPDATE_INTERVAL_HOURS: int = 12

    class Config:
        env_file = ".env"


settings = PocGithubParserSettings()