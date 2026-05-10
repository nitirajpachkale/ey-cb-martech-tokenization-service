from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    JWT_SECRET_KEY: str
    JWT_EXPIRE_SECONDS: int
    ALGORITHM: str
    APP_KEY: str
    ENC_PAYLOAD_KEY: str
    ENC_TOKEN_KEY: str
    ENC_LOG_KEY: str
    SQLALCHEMY_DATABASE_URL: str
    ENCRYPTION_ENABLED: bool

    class Config:
        env_file = ".env"

settings = Settings()
