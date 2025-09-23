from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Index
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base


class DeviceAccess(Base):
    """Device access model for tracking access history and patterns"""

    __tablename__ = "device_access"

    # Composite primary key (device_id + timestamp)
    device_id = Column(Integer, ForeignKey('devices.id'), primary_key=True)
    timestamp = Column(DateTime(timezone=True), primary_key=True, server_default=func.now())

    # Access data
    ip_address = Column(String(45), nullable=False)  # IPv6 max length
    location_data = Column(JSON, nullable=True)  # {"lat": float, "lng": float, "country": str, "city": str}
    asn = Column(String(50), nullable=True)  # Autonomous System Number
    risk_factors = Column(JSON, nullable=True)  # Risk factors detected during this access

    # Hardware and browser information (for advanced validation)
    hardware_info = Column(JSON, nullable=True)  # {"cpu_cores": int, "ram_gb": float, "screen_resolution": str}
    browser_info = Column(JSON, nullable=True)  # {"user_agent": str, "is_headless": bool, "automation_detected": bool}

    # Relationship with device
    device = relationship("Device", back_populates="accesses")

    # Indexes for efficient queries
    __table_args__ = (
        Index('idx_device_timestamp', 'device_id', 'timestamp'),
        Index('idx_timestamp', 'timestamp'),  # For global time-based queries
        Index('idx_ip_address', 'ip_address'),  # For IP-based analysis
    )

    def __repr__(self):
        return f"<DeviceAccess(device_id={self.device_id}, timestamp='{self.timestamp}', ip='{self.ip_address}')>"

    def to_dict(self):
        """Convert device access to dictionary"""
        return {
            "device_id": self.device_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip_address": self.ip_address,
            "location_data": self.location_data,
            "asn": self.asn,
            "risk_factors": self.risk_factors,
            "hardware_info": self.hardware_info,
            "browser_info": self.browser_info
        }

    @property
    def latitude(self):
        """Get latitude from location data"""
        return self.location_data.get('lat') if self.location_data else None

    @property
    def longitude(self):
        """Get longitude from location data"""
        return self.location_data.get('lng') if self.location_data else None

    @property
    def country(self):
        """Get country from location data"""
        return self.location_data.get('country') if self.location_data else None

    @property
    def city(self):
        """Get city from location data"""
        return self.location_data.get('city') if self.location_data else None

    def has_location(self):
        """Check if access has location data for travel detection"""
        return (self.location_data and
                'lat' in self.location_data and
                'lng' in self.location_data and
                self.location_data['lat'] is not None and
                self.location_data['lng'] is not None)

    def get_coordinates(self):
        """Get coordinates tuple for distance calculations"""
        if self.has_location():
            return (self.location_data['lat'], self.location_data['lng'])
        return None