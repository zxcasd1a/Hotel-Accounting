import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://user:password@localhost/identitydb" # Default, should be in .env

    class Config:
        env_file = ".env"

settings = Settings()

SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """
    Dependency to get a database session.
    Ensures the session is closed after the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Optional: Function to create all tables (for initial setup, usually handled by Alembic in production)
def create_database_tables():
    # This should be called only once, perhaps in main.py on startup if not using Alembic
    # In a real app, Alembic migrations would handle this.
    Base.metadata.create_all(bind=engine)

# Example .env file content (not created by the agent, user should create this):
# DATABASE_URL="postgresql://your_db_user:your_db_password@your_db_host:your_db_port/your_db_name"
