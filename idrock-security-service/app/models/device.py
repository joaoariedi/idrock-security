from sqlalchemy import Column, Integer, String, Boolean, DateTime, Index, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base


class Device(Base):
    """Device model for tracking user devices and trust status"""

    __tablename__ = "devices"

    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # Device identification - SECURITY CRITICAL: unique constraint prevents fingerprint duplication
    user_id = Column(String(255), index=True, nullable=False)
    device_fingerprint = Column(String(255), index=True, nullable=False)

    # Trust status
    is_trusted = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationship with device accesses
    accesses = relationship("DeviceAccess", back_populates="device", cascade="all, delete-orphan")

    # Security constraints and indexes
    __table_args__ = (
        # SECURITY CONSTRAINT: Prevents duplicated user_id + device_fingerprint combinations
        # This prevents fingerprint cloning attacks and ensures device uniqueness
        UniqueConstraint('user_id', 'device_fingerprint', name='uq_user_device_fingerprint'),
        # Performance index for efficient lookups
        Index('idx_user_device', 'user_id', 'device_fingerprint'),
    )

    def __repr__(self):
        return f"<Device(id={self.id}, user_id='{self.user_id}', fingerprint='{self.device_fingerprint[:20]}...', trusted={self.is_trusted})>"

    def to_dict(self):
        """Convert device to dictionary"""
        return {
            "device_id": self.id,
            "user_id": self.user_id,
            "device_fingerprint": self.device_fingerprint,
            "is_trusted": self.is_trusted,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "access_count": len(self.accesses) if self.accesses else 0
        }

    def mark_trusted(self):
        """Mark device as trusted"""
        self.is_trusted = True
        self.updated_at = func.now()

    def revoke_trust(self):
        """Revoke device trust status"""
        self.is_trusted = False
        self.updated_at = func.now()