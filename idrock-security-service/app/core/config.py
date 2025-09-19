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

    # Legacy settings for compatibility (will be ignored)
    idrock_secret_key: Optional[str] = None
    idrock_api_key: Optional[str] = None
    jwt_secret: Optional[str] = None
    bcrypt_rounds: Optional[str] = None
    idrock_api_url: Optional[str] = None
    nexshop_api_url: Optional[str] = None
    cors_origin: Optional[str] = None

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds

    # Risk Assessment Settings
    allow_threshold: int = 70
    review_threshold: int = 30

    class Config:
        env_file = ".env"
        extra = "allow"  # Allow extra fields to prevent validation errors


settings = Settings()