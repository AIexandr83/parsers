import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://cve_user:cve_password@postgres_db:5432/cve_database",
    )

    class Config:
        env_file = ".env"


settings = Settings()
