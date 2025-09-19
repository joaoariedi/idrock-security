from pydantic import BaseModel, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import ipaddress

from app.schemas.common import BaseRequest, BaseResponse, RiskLevel


class LocationData(BaseModel):
    """Geographic location data model"""
    lat: float = Field(..., ge=-90, le=90, description="Latitude coordinate")
    lng: float = Field(..., ge=-180, le=180, description="Longitude coordinate")
    country: Optional[str] = Field(None, max_length=3, description="Country code (ISO 3166-1 alpha-2)")
    city: Optional[str] = Field(None, max_length=100, description="City name")


class HardwareInfo(BaseModel):
    """Hardware specification data model"""
    cpu_cores: Optional[int] = Field(None, ge=1, le=128, description="Number of CPU cores")
    ram_gb: Optional[float] = Field(None, ge=0.1, le=1024, description="RAM amount in GB")
    screen_resolution: Optional[str] = Field(None, max_length=20, description="Screen resolution (e.g., '1920x1080')")
    platform: Optional[str] = Field(None, max_length=50, description="Platform identifier")
    timezone: Optional[str] = Field(None, max_length=20, description="Timezone offset")
    language: Optional[str] = Field(None, max_length=10, description="Browser language")


class BrowserInfo(BaseModel):
    """Browser environment data model"""
    user_agent: str = Field(..., min_length=1, max_length=1000, description="User-Agent string")
    has_plugins: Optional[bool] = Field(None, description="Browser has plugins")
    plugin_count: Optional[int] = Field(None, ge=0, description="Number of browser plugins")
    has_webgl: Optional[bool] = Field(None, description="WebGL support available")
    has_canvas: Optional[bool] = Field(None, description="Canvas support available")
    screen_depth: Optional[int] = Field(None, ge=1, le=64, description="Screen color depth")
    languages: Optional[List[str]] = Field(None, description="Browser supported languages")
    navigator_properties: Optional[Dict[str, Any]] = Field(None, description="Navigator object properties")


class DeviceRegistrationRequest(BaseRequest):
    """Device registration request model"""
    user_id: str = Field(..., min_length=1, max_length=255, description="Unique user identifier")
    device_fingerprint: str = Field(..., min_length=1, max_length=255, description="Unique device fingerprint")
    hardware_info: Optional[HardwareInfo] = None
    browser_info: Optional[BrowserInfo] = None

    class Config:
        schema_extra = {
            "example": {
                "user_id": "user123",
                "device_fingerprint": "fp_advanced_device_chrome_v2",
                "hardware_info": {
                    "cpu_cores": 8,
                    "ram_gb": 16.0,
                    "screen_resolution": "2560x1440",
                    "platform": "Win32",
                    "timezone": "-180",
                    "language": "en-US"
                },
                "browser_info": {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "has_plugins": True,
                    "plugin_count": 3,
                    "has_webgl": True,
                    "has_canvas": True,
                    "screen_depth": 24,
                    "languages": ["en-US", "en"],
                    "navigator_properties": {}
                }
            }
        }


class DeviceAccessRequest(BaseRequest):
    """Device access logging request model"""
    device_id: int = Field(..., ge=1, description="Device ID")
    ip_address: str = Field(..., description="Client IP address")
    location_data: Optional[LocationData] = None
    asn: Optional[str] = Field(None, max_length=50, description="Autonomous System Number")
    hardware_info: Optional[HardwareInfo] = None
    browser_info: Optional[BrowserInfo] = None

    @validator('ip_address')
    def validate_ip_address(cls, v):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')

    class Config:
        schema_extra = {
            "example": {
                "device_id": 1,
                "ip_address": "203.0.113.1",
                "location_data": {
                    "lat": 35.6762,
                    "lng": 139.6503,
                    "country": "JP",
                    "city": "Tokyo"
                },
                "asn": "AS2516",
                "hardware_info": {
                    "cpu_cores": 8,
                    "ram_gb": 16.0,
                    "screen_resolution": "2560x1440"
                },
                "browser_info": {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            }
        }


class DeviceTrustUpdateRequest(BaseRequest):
    """Device trust status update request model"""
    is_trusted: bool = Field(..., description="New trust status for device")
    admin_user: Optional[str] = Field(None, max_length=255, description="Admin user making the change")

    class Config:
        schema_extra = {
            "example": {
                "is_trusted": True,
                "admin_user": "admin123"
            }
        }


class DeviceInfo(BaseModel):
    """Device information response model"""
    device_id: int = Field(..., description="Device ID")
    user_id: str = Field(..., description="User ID")
    device_fingerprint: str = Field(..., description="Device fingerprint")
    is_trusted: bool = Field(..., description="Trust status")
    created_at: datetime = Field(..., description="Device creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    access_count: int = Field(..., ge=0, description="Number of recorded accesses")


class DeviceAccessInfo(BaseModel):
    """Device access information response model"""
    device_id: int = Field(..., description="Device ID")
    timestamp: datetime = Field(..., description="Access timestamp")
    ip_address: str = Field(..., description="IP address")
    location_data: Optional[LocationData] = None
    asn: Optional[str] = None
    risk_factors: Optional[Dict[str, Any]] = None


class DeviceRegistrationResponse(BaseResponse):
    """Device registration response model"""
    device: DeviceInfo
    is_new_device: bool = Field(..., description="True if device was newly created")
    risk_assessment: Optional[Dict[str, Any]] = Field(None, description="Initial risk assessment")

    class Config:
        schema_extra = {
            "example": {
                "device": {
                    "device_id": 1,
                    "user_id": "user123",
                    "device_fingerprint": "fp_advanced_device_chrome_v2",
                    "is_trusted": False,
                    "created_at": "2025-09-19T10:30:00Z",
                    "updated_at": None,
                    "access_count": 0
                },
                "is_new_device": True,
                "risk_assessment": {
                    "new_device_detected": True,
                    "hardware_validation": "passed",
                    "browser_validation": "passed"
                },
                "timestamp": "2025-09-19T10:30:00Z",
                "request_id": "req_device_123",
                "api_version": "1.0.0-mvp"
            }
        }


class DeviceAccessResponse(BaseResponse):
    """Device access logging response model"""
    access_logged: bool = Field(..., description="Whether access was successfully logged")
    risk_factors: Optional[Dict[str, Any]] = Field(None, description="Risk factors detected")
    travel_analysis: Optional[Dict[str, Any]] = Field(None, description="Travel feasibility analysis")

    class Config:
        schema_extra = {
            "example": {
                "access_logged": True,
                "risk_factors": {
                    "asn_change": False,
                    "temporal_anomaly": 0.1,
                    "hardware_validation": "passed"
                },
                "travel_analysis": {
                    "is_feasible": True,
                    "travel_speed_kmh": 45.2,
                    "distance_km": 12.8,
                    "risk_level": "ALLOW"
                },
                "timestamp": "2025-09-19T10:30:00Z",
                "request_id": "req_access_123",
                "api_version": "1.0.0-mvp"
            }
        }


class DeviceListResponse(BaseResponse):
    """Device list response model"""
    devices: List[DeviceInfo] = Field(..., description="List of user devices")
    total_devices: int = Field(..., ge=0, description="Total number of devices")
    trusted_devices: int = Field(..., ge=0, description="Number of trusted devices")

    class Config:
        schema_extra = {
            "example": {
                "devices": [
                    {
                        "device_id": 1,
                        "user_id": "user123",
                        "device_fingerprint": "fp_device_1",
                        "is_trusted": True,
                        "created_at": "2025-09-19T10:30:00Z",
                        "updated_at": "2025-09-19T12:00:00Z",
                        "access_count": 15
                    }
                ],
                "total_devices": 1,
                "trusted_devices": 1,
                "timestamp": "2025-09-19T10:30:00Z",
                "request_id": "req_list_123",
                "api_version": "1.0.0-mvp"
            }
        }


class DeviceHistoryResponse(BaseResponse):
    """Device access history response model"""
    accesses: List[DeviceAccessInfo] = Field(..., description="List of device accesses")
    total_accesses: int = Field(..., ge=0, description="Total number of accesses")
    analysis_period_days: int = Field(..., ge=1, description="Analysis period in days")
    patterns: Optional[Dict[str, Any]] = Field(None, description="Access pattern analysis")

    class Config:
        schema_extra = {
            "example": {
                "accesses": [
                    {
                        "device_id": 1,
                        "timestamp": "2025-09-19T10:30:00Z",
                        "ip_address": "192.168.1.100",
                        "location_data": {
                            "lat": -23.5505,
                            "lng": -46.6333,
                            "country": "BR",
                            "city": "São Paulo"
                        },
                        "asn": "AS7738"
                    }
                ],
                "total_accesses": 1,
                "analysis_period_days": 30,
                "patterns": {
                    "most_common_hour": "14",
                    "unique_countries": 1,
                    "unique_asns": 1
                },
                "timestamp": "2025-09-19T10:30:00Z",
                "request_id": "req_history_123",
                "api_version": "1.0.0-mvp"
            }
        }