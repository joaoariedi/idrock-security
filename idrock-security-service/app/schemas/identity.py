from pydantic import BaseModel, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import ipaddress

from app.schemas.common import BaseRequest, BaseResponse, RiskLevel, ActionType


class SessionData(BaseModel):
    """Session data model"""
    timestamp: datetime
    device_fingerprint: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


class Context(BaseModel):
    """Request context model"""
    action_type: ActionType
    amount: Optional[float] = Field(None, ge=0, description="Transaction amount for financial operations")
    additional_context: Optional[Dict[str, Any]] = None


class IdentityVerificationRequest(BaseRequest):
    """Identity verification request model"""
    user_id: str = Field(..., min_length=1, max_length=255, description="Unique user identifier")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str = Field(..., min_length=1, description="Client user agent string")
    session_data: SessionData
    context: Context
    
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
                "user_id": "user123",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "session_data": {
                    "timestamp": "2025-09-07T10:30:00Z",
                    "device_fingerprint": "fp_abc123def456",
                    "additional_data": {
                        "browser": "Chrome",
                        "screen_resolution": "1920x1080"
                    }
                },
                "context": {
                    "action_type": "login",
                    "amount": None,
                    "additional_context": {
                        "login_attempt_count": 1,
                        "last_login": "2025-09-06T15:30:00Z"
                    }
                }
            }
        }


class RiskFactor(BaseModel):
    """Risk factor analysis model"""
    factor: str = Field(..., description="Risk factor type (e.g., 'ip_reputation')")
    score: int = Field(..., ge=0, le=100, description="Risk factor score (0-100)")
    weight: float = Field(..., ge=0, le=1, description="Weight of this factor in overall score")
    details: str = Field(..., description="Human-readable details about the risk factor")
    proxycheck_data: Optional[Dict[str, Any]] = Field(None, description="Raw ProxyCheck.io response data")


class Recommendation(BaseModel):
    """Risk assessment recommendation model"""
    action: str = Field(..., description="Recommended action")
    priority: str = Field(..., description="Priority level (low, medium, high)")
    message: str = Field(..., description="Human-readable recommendation message")


class AssessmentMetadata(BaseModel):
    """Assessment metadata model"""
    processing_time_ms: int = Field(..., ge=0, description="Processing time in milliseconds")
    api_version: str = "1.0.0-mvp"
    request_id: str = Field(..., description="Unique request identifier")
    mvp_scope: str = "ip_reputation_only"


class IdentityVerificationResponse(BaseResponse):
    """Identity verification response model"""
    confidence_score: int = Field(..., ge=0, le=100, description="Overall confidence score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk level determination")
    risk_factors: List[RiskFactor] = Field(..., description="Detailed risk factor analysis")
    recommendations: List[Recommendation] = Field(..., description="Risk-based recommendations")
    metadata: AssessmentMetadata
    
    class Config:
        schema_extra = {
            "example": {
                "confidence_score": 85,
                "risk_level": "ALLOW",
                "risk_factors": [
                    {
                        "factor": "ip_reputation",
                        "score": 85,
                        "weight": 1.0,
                        "details": "Clean IP with good reputation from ProxyCheck.io",
                        "proxycheck_data": {
                            "proxy": "no",
                            "type": "Residential",
                            "risk": 1,
                            "country": "US",
                            "provider": "AT&T"
                        }
                    }
                ],
                "recommendations": [
                    {
                        "action": "allow_with_standard_monitoring",
                        "priority": "low",
                        "message": "Transaction approved - good IP reputation"
                    }
                ],
                "metadata": {
                    "processing_time_ms": 85,
                    "api_version": "1.0.0-mvp",
                    "request_id": "req_abc123def456",
                    "mvp_scope": "ip_reputation_only"
                },
                "timestamp": "2025-09-07T10:30:15Z",
                "request_id": "req_abc123def456",
                "api_version": "1.0.0-mvp"
            }
        }