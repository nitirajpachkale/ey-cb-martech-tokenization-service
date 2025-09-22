from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

DATABASE_URL = settings.SQLALCHEMY_DATABASE_URL

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to be used in endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
