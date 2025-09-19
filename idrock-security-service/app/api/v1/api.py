from fastapi import APIRouter

from app.api.v1.endpoints import health, identity, devices

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(identity.router, prefix="/identity", tags=["Identity"])
api_router.include_router(devices.router, prefix="/devices", tags=["Devices"])