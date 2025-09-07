from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from app.core.config import settings
from app.core.database import create_tables
from app.api.v1.api import api_router


def create_application() -> FastAPI:
    """Create and configure FastAPI application"""
    
    # Create FastAPI app
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="IP Reputation Security Tool for Fraud Risk Assessment",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    # Add CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API router
    application.include_router(api_router, prefix=settings.api_v1_str)
    
    return application


def custom_openapi():
    """Custom OpenAPI schema generation"""
    if app.openapi_schema:
        return app.openapi_schema
        
    openapi_schema = get_openapi(
        title=settings.app_name,
        version=settings.app_version,
        description="""
        ## IDROCK Security Service API
        
        The IDROCK Security Service provides real-time fraud risk assessment through IP reputation analysis.
        
        ### Features:
        - **Real-time risk assessment** for login, checkout, and sensitive operations
        - **IP reputation analysis** using ProxyCheck.io integration
        - **Confidence scoring** (0-100) with adaptive risk thresholds
        - **Assessment history** with filtering and pagination
        
        ### Risk Levels:
        - **ALLOW (70-100)**: Low risk, automatic approval
        - **REVIEW (30-69)**: Medium risk, additional verification required
        - **DENY (0-29)**: High risk, block transaction
        
        ### MVP Scope:
        This MVP version focuses on IP reputation analysis only. Future versions will include:
        - Behavioral analysis
        - Device fingerprinting
        - Machine learning models
        """,
        routes=app.routes,
    )
    
    # Add custom info
    openapi_schema["info"]["x-logo"] = {
        "url": "https://idrock.com/logo.png"
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Create the FastAPI application
app = create_application()
app.openapi = custom_openapi


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    create_tables()
    print(f"🚀 {settings.app_name} v{settings.app_version} starting up...")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    print(f"🛑 {settings.app_name} shutting down...")


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "api_base": settings.api_v1_str,
        "mvp_scope": "ip_reputation_only"
    }