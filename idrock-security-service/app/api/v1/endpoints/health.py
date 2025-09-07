from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
import platform
import sys

from app.core.database import get_db
from app.core.config import settings
from app.schemas.health import HealthResponse, SystemInfo, DatabaseInfo

router = APIRouter()


@router.get("/", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint
    
    Returns comprehensive system health information including:
    - Service status and version
    - Database connectivity status
    - System information
    - Configuration status
    """
    
    # Check database connectivity
    db_status = "healthy"
    db_error = None
    try:
        # Simple database query to check connectivity
        db.execute(text("SELECT 1"))
        db.commit()
    except Exception as e:
        db_status = "unhealthy"
        db_error = str(e)
    
    # System information
    system_info = SystemInfo(
        platform=platform.platform(),
        python_version=sys.version,
        cpu_count=platform.processor() if platform.processor() else "unknown",
        architecture=platform.architecture()[0]
    )
    
    # Database information
    database_info = DatabaseInfo(
        status=db_status,
        url_scheme="sqlite" if "sqlite" in settings.database_url else "unknown",
        error=db_error
    )
    
    # Overall service status
    service_status = "healthy" if db_status == "healthy" else "degraded"
    
    return HealthResponse(
        status=service_status,
        timestamp=datetime.utcnow(),
        version=settings.app_version,
        service_name=settings.app_name,
        system=system_info,
        database=database_info,
        configuration={
            "debug_mode": settings.debug,
            "proxycheck_configured": bool(settings.proxycheck_api_key),
            "rate_limiting": {
                "requests_per_window": settings.rate_limit_requests,
                "window_seconds": settings.rate_limit_window
            },
            "risk_thresholds": {
                "allow": settings.allow_threshold,
                "review": settings.review_threshold
            }
        }
    )