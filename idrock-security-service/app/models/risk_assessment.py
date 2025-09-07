from sqlalchemy import Column, Integer, String, Text, DateTime, Float, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class RiskAssessment(Base):
    """Risk assessment model for storing security assessments"""
    
    __tablename__ = "risk_assessments"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Request identification
    request_id = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(String(255), index=True, nullable=False)
    
    # Request data
    ip_address = Column(String(45), index=True, nullable=False)  # IPv6 max length
    user_agent = Column(Text, nullable=False)
    action_type = Column(String(50), index=True, nullable=False)
    transaction_amount = Column(Float, nullable=True)
    
    # Risk assessment results
    confidence_score = Column(Integer, nullable=False, index=True)
    risk_level = Column(String(10), nullable=False, index=True)
    
    # Analysis data (JSON format for flexibility)
    risk_factors = Column(JSON, nullable=False)
    recommendations = Column(JSON, nullable=False)
    session_data = Column(JSON, nullable=True)
    proxycheck_response = Column(JSON, nullable=True)
    
    # Processing metadata
    processing_time_ms = Column(Integer, nullable=False)
    api_version = Column(String(20), nullable=False, default="1.0.0-mvp")
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def __repr__(self):
        return f"<RiskAssessment(id={self.id}, user_id='{self.user_id}', risk_level='{self.risk_level}', score={self.confidence_score})>"
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "assessment_id": self.request_id,
            "user_id": self.user_id,
            "timestamp": self.created_at.isoformat() if self.created_at else None,
            "ip_address": self.ip_address,
            "confidence_score": self.confidence_score,
            "risk_level": self.risk_level,
            "action_type": self.action_type,
            "risk_factors": self.risk_factors,
            "device_fingerprint": self.session_data.get("device_fingerprint") if self.session_data else None,
            "user_agent": self.user_agent,
            "processing_time_ms": self.processing_time_ms,
            "transaction_amount": self.transaction_amount
        }