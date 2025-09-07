from pydantic import BaseModel, validator, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from app.schemas.common import BaseResponse


class HistoryFilters(BaseModel):
    """History endpoint filter parameters"""
    user_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    risk_level: Optional[str] = None
    action_type: Optional[str] = None
    page: int = Field(1, ge=1)
    limit: int = Field(50, ge=1, le=500)
    format: str = Field("json", pattern="^(json|csv)$")
    
    @validator('end_date')
    def validate_date_range(cls, v, values):
        """Validate that end_date is after start_date"""
        if v and values.get('start_date'):
            if v <= values['start_date']:
                raise ValueError('end_date must be after start_date')
        return v


class AssessmentRecord(BaseModel):
    """Individual assessment record in history"""
    assessment_id: str = Field(..., description="Unique assessment identifier")
    user_id: str = Field(..., description="User identifier")
    timestamp: datetime = Field(..., description="Assessment timestamp")
    ip_address: str = Field(..., description="Client IP address")
    confidence_score: int = Field(..., ge=0, le=100, description="Confidence score (0-100)")
    risk_level: str = Field(..., description="Risk level (ALLOW/REVIEW/DENY)")
    action_type: str = Field(..., description="Action type (login/checkout/sensitive_action)")
    risk_factors: List[Dict[str, Any]] = Field(..., description="Risk factor analysis")
    device_fingerprint: Optional[str] = Field(None, description="Device fingerprint if available")
    user_agent: str = Field(..., description="Client user agent")
    processing_time_ms: int = Field(..., ge=0, description="Processing time in milliseconds")
    transaction_amount: Optional[float] = Field(None, description="Transaction amount if applicable")
    
    class Config:
        schema_extra = {
            "example": {
                "assessment_id": "req_abc123def456",
                "user_id": "user123",
                "timestamp": "2025-09-07T10:30:00Z",
                "ip_address": "192.168.1.100",
                "confidence_score": 85,
                "risk_level": "ALLOW",
                "action_type": "login",
                "risk_factors": [
                    {
                        "factor": "ip_reputation",
                        "score": 85,
                        "weight": 1.0,
                        "details": "Clean IP with good reputation"
                    }
                ],
                "device_fingerprint": "fp_abc123",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "processing_time_ms": 145,
                "transaction_amount": None
            }
        }


class PaginationInfo(BaseModel):
    """Pagination metadata"""
    current_page: int = Field(..., description="Current page number")
    total_pages: int = Field(..., description="Total number of pages")
    total_records: int = Field(..., description="Total number of records")
    records_per_page: int = Field(..., description="Records per page")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_previous: bool = Field(..., description="Whether there is a previous page")


class AppliedFilters(BaseModel):
    """Summary of applied filters"""
    user_id: Optional[str] = None
    date_range: Optional[str] = None
    risk_level: Optional[str] = None
    action_type: Optional[str] = None


class HistoryResponseMetadata(BaseModel):
    """History response metadata"""
    request_id: str = Field(..., description="Unique request identifier")
    response_time_ms: int = Field(..., description="Response processing time")
    api_version: str = Field(default="1.0.0", description="API version")


class HistoryResponse(BaseResponse):
    """History endpoint response model"""
    data: List[AssessmentRecord] = Field(..., description="Assessment records")
    pagination: PaginationInfo = Field(..., description="Pagination information")
    filters_applied: AppliedFilters = Field(..., description="Applied filter summary")
    metadata: HistoryResponseMetadata = Field(..., description="Response metadata")
    
    class Config:
        schema_extra = {
            "example": {
                "data": [
                    {
                        "assessment_id": "req_abc123def456",
                        "user_id": "user123",
                        "timestamp": "2025-09-07T10:30:00Z",
                        "ip_address": "192.168.1.100",
                        "confidence_score": 85,
                        "risk_level": "ALLOW",
                        "action_type": "login",
                        "risk_factors": [
                            {
                                "factor": "ip_reputation",
                                "score": 85,
                                "weight": 1.0,
                                "details": "Clean IP with good reputation"
                            }
                        ],
                        "device_fingerprint": "fp_abc123",
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "processing_time_ms": 145,
                        "transaction_amount": None
                    }
                ],
                "pagination": {
                    "current_page": 1,
                    "total_pages": 10,
                    "total_records": 500,
                    "records_per_page": 50,
                    "has_next": True,
                    "has_previous": False
                },
                "filters_applied": {
                    "user_id": "user123",
                    "date_range": "2025-09-01 to 2025-09-07",
                    "risk_level": "ALLOW",
                    "action_type": "login"
                },
                "metadata": {
                    "request_id": "hist_abc123def456",
                    "response_time_ms": 25,
                    "api_version": "1.0.0"
                },
                "timestamp": "2025-09-07T10:30:15Z",
                "request_id": "hist_abc123def456",
                "api_version": "1.0.0"
            }
        }