import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings loaded from environment or .env file."""
    APP_NAME: str = "ForenX-Sentinel"
    VERSION: str = "1.0.0"
    
    # Server configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    
    # Database configuration
    DATABASE_URL: str = "sqlite:///./forenx.db"
    
    # Analysis thresholds
    ENDPOINT_ABUSE_THRESHOLD: int = 100  # Requests per hour
    DATA_DUMP_THRESHOLD: int = 10000000  # 10MB
    IP_REQUESTS_PER_MINUTE_THRESHOLD: int = 60
    
    class Config:
        env_file = ".env"

settings = Settings()
