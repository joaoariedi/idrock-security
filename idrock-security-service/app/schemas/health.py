from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


class SystemInfo(BaseModel):
    """System information model"""
    platform: str
    python_version: str
    cpu_count: str
    architecture: str


class DatabaseInfo(BaseModel):
    """Database information model"""
    status: str
    url_scheme: str
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: datetime
    version: str
    service_name: str
    system: SystemInfo
    database: DatabaseInfo
    configuration: Dict[str, Any]
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2025-09-07T10:30:00Z",
                "version": "1.0.0-mvp",
                "service_name": "IDROCK Security Service",
                "system": {
                    "platform": "Linux-5.4.0-generic-x86_64",
                    "python_version": "3.9.0",
                    "cpu_count": "Intel Core i7",
                    "architecture": "64bit"
                },
                "database": {
                    "status": "healthy",
                    "url_scheme": "sqlite",
                    "error": None
                },
                "configuration": {
                    "debug_mode": False,
                    "proxycheck_configured": True,
                    "rate_limiting": {
                        "requests_per_window": 100,
                        "window_seconds": 60
                    },
                    "risk_thresholds": {
                        "allow": 70,
                        "review": 30
                    }
                }
            }
        }