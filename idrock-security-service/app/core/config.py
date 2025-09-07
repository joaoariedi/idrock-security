from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """IDROCK Security Service Configuration"""
    
    # Application Settings
    app_name: str = "IDROCK Security Service"
    app_version: str = "1.0.0-mvp"
    debug: bool = False
    
    # API Settings
    api_v1_str: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Database Settings
    database_url: str = "sqlite:///./idrock_security.db"
    
    # External API Settings
    proxycheck_api_key: Optional[str] = None
    proxycheck_api_url: str = "https://proxycheck.io/v2/"
    proxycheck_timeout: int = 5
    
    # Security Settings
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    
    # Risk Assessment Settings
    allow_threshold: int = 70
    review_threshold: int = 30
    
    class Config:
        env_file = ".env"


settings = Settings()