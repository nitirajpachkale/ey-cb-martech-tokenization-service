from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_SECRET_KEY: str
    JWT_EXPIRE_SECONDS: int
    ALGORITHM: str
    APP_KEY: str
    ENC_SECRET_KEY: str
    SQLALCHEMY_DATABASE_URL: str
    UNAME: str
    UPWD: str
    ENCRYPTION_ENABLED: bool

    class Config:
        env_file = ".env"

settings = Settings()
