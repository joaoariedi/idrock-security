from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class AuditLog(Base):
    """Audit log model for compliance and monitoring"""
    
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Event identification
    event_type = Column(String(100), nullable=False, index=True)
    event_category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="INFO")
    
    # Request context
    request_id = Column(String(255), index=True, nullable=True)
    user_id = Column(String(255), index=True, nullable=True)
    ip_address = Column(String(45), nullable=True)
    
    # Event details
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    
    # Error information (if applicable)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event_type='{self.event_type}', severity='{self.severity}')>"
    
    @classmethod
    def log_assessment_request(cls, request_id: str, user_id: str, ip_address: str, action_type: str):
        """Create audit log for assessment request"""
        return cls(
            event_type="assessment_request",
            event_category="security",
            severity="INFO",
            request_id=request_id,
            user_id=user_id,
            ip_address=ip_address,
            message=f"Risk assessment requested for user {user_id} from IP {ip_address}",
            details={
                "action_type": action_type,
                "request_source": "api"
            }
        )
    
    @classmethod
    def log_assessment_result(cls, request_id: str, user_id: str, risk_level: str, confidence_score: int):
        """Create audit log for assessment result"""
        severity = "WARN" if risk_level == "DENY" else "INFO"
        return cls(
            event_type="assessment_result",
            event_category="security",
            severity=severity,
            request_id=request_id,
            user_id=user_id,
            message=f"Risk assessment completed: {risk_level} (score: {confidence_score})",
            details={
                "risk_level": risk_level,
                "confidence_score": confidence_score
            }
        )
    
    @classmethod
    def log_error(cls, event_type: str, error_message: str, request_id: str = None, user_id: str = None, details: dict = None):
        """Create audit log for errors"""
        return cls(
            event_type=event_type,
            event_category="error",
            severity="ERROR",
            request_id=request_id,
            user_id=user_id,
            message=f"Error in {event_type}: {error_message}",
            error_message=error_message,
            details=details
        )