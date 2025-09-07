from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level enumeration"""
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


class ActionType(str, Enum):
    """Action type enumeration"""
    LOGIN = "login"
    CHECKOUT = "checkout"
    SENSITIVE_ACTION = "sensitive_action"


class BaseResponse(BaseModel):
    """Base response model with common fields"""
    timestamp: datetime
    request_id: str
    api_version: str = "1.0.0-mvp"


class BaseRequest(BaseModel):
    """Base request model with common validation"""
    class Config:
        # Enable arbitrary types
        arbitrary_types_allowed = True
        # Validate assignment
        validate_assignment = True
        # Use enum values
        use_enum_values = True