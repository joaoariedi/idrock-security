from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_
from app.models.device import Device
from app.models.device_access import DeviceAccess
from app.models.audit_log import AuditLog


class DeviceAccessService:
    """Service for managing device access history and pattern analysis"""

    @staticmethod
    def record_access(
        db: Session,
        device_id: int,
        ip_address: str,
        location_data: Optional[Dict[str, Any]] = None,
        asn: Optional[str] = None,
        hardware_info: Optional[Dict[str, Any]] = None,
        browser_info: Optional[Dict[str, Any]] = None,
        risk_factors: Optional[Dict[str, Any]] = None
    ) -> DeviceAccess:
        """Record a new device access"""
        access = DeviceAccess(
            device_id=device_id,
            ip_address=ip_address,
            location_data=location_data,
            asn=asn,
            hardware_info=hardware_info,
            browser_info=browser_info,
            risk_factors=risk_factors
        )

        db.add(access)
        db.flush()  # Flush to get the timestamp without committing

        # Store timestamp for later query
        access_timestamp = access.timestamp

        db.commit()

        # Get the access back from database to ensure it's properly attached
        access = db.query(DeviceAccess).filter(
            DeviceAccess.device_id == device_id,
            DeviceAccess.timestamp == access_timestamp
        ).first()

        # Log access for audit trail
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            audit_log = AuditLog(
                event_type="device_access_recorded",
                event_category="security",
                severity="INFO",
                user_id=device.user_id,
                message=f"Device access recorded from IP {ip_address}",
                details={
                    "device_id": device_id,
                    "ip_address": ip_address,
                    "location": location_data.get('city', 'Unknown') if location_data else 'Unknown',
                    "asn": asn,
                    "has_risk_factors": bool(risk_factors)
                }
            )
            db.add(audit_log)
            db.commit()

        return access

    @staticmethod
    def get_latest_access(db: Session, device_id: int) -> Optional[DeviceAccess]:
        """Get the most recent access for a device"""
        return db.query(DeviceAccess).filter(
            DeviceAccess.device_id == device_id
        ).order_by(desc(DeviceAccess.timestamp)).first()

    @staticmethod
    def get_latest_user_access(db: Session, user_id: str) -> Optional[DeviceAccess]:
        """Get the most recent access for any device of a user"""
        return db.query(DeviceAccess).join(Device).filter(
            Device.user_id == user_id
        ).order_by(desc(DeviceAccess.timestamp)).first()

    @staticmethod
    def get_access_history(
        db: Session,
        device_id: int,
        limit: int = 100,
        days_back: int = 30
    ) -> List[DeviceAccess]:
        """Get access history for a device"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)

        return db.query(DeviceAccess).filter(
            and_(
                DeviceAccess.device_id == device_id,
                DeviceAccess.timestamp >= cutoff_date
            )
        ).order_by(desc(DeviceAccess.timestamp)).limit(limit).all()

    @staticmethod
    def get_user_access_history(
        db: Session,
        user_id: str,
        limit: int = 100,
        days_back: int = 30
    ) -> List[DeviceAccess]:
        """Get access history for all devices of a user"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)

        return db.query(DeviceAccess).join(Device).filter(
            and_(
                Device.user_id == user_id,
                DeviceAccess.timestamp >= cutoff_date
            )
        ).order_by(desc(DeviceAccess.timestamp)).limit(limit).all()

    @staticmethod
    def get_access_pattern_data(db: Session, user_id: str, days_back: int = 30) -> Dict[str, Any]:
        """
        Get user access pattern data for behavioral analysis.

        Returns patterns for:
        - Hourly access distribution
        - Daily access distribution
        - Geographic patterns
        - ASN patterns
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)

        accesses = db.query(DeviceAccess).join(Device).filter(
            and_(
                Device.user_id == user_id,
                DeviceAccess.timestamp >= cutoff_date
            )
        ).all()

        # Initialize pattern data
        hourly_pattern = {str(i): 0 for i in range(24)}
        daily_pattern = {str(i): 0 for i in range(7)}  # 0=Monday, 6=Sunday
        geographic_pattern = {}
        asn_pattern = {}
        ip_pattern = {}

        for access in accesses:
            # Hourly pattern
            hour = access.timestamp.hour
            hourly_pattern[str(hour)] += 1

            # Daily pattern (weekday)
            weekday = access.timestamp.weekday()
            daily_pattern[str(weekday)] += 1

            # Geographic pattern
            if access.location_data and access.country:
                country = access.country
                geographic_pattern[country] = geographic_pattern.get(country, 0) + 1

            # ASN pattern
            if access.asn:
                asn_pattern[access.asn] = asn_pattern.get(access.asn, 0) + 1

            # IP pattern
            ip_pattern[access.ip_address] = ip_pattern.get(access.ip_address, 0) + 1

        return {
            "analysis_period_days": days_back,
            "total_accesses": len(accesses),
            "hourly_distribution": hourly_pattern,
            "daily_distribution": daily_pattern,
            "geographic_distribution": geographic_pattern,
            "asn_distribution": asn_pattern,
            "ip_distribution": ip_pattern,
            "most_common_hour": max(hourly_pattern, key=hourly_pattern.get),
            "most_common_day": max(daily_pattern, key=daily_pattern.get),
            "unique_countries": len(geographic_pattern),
            "unique_asns": len(asn_pattern),
            "unique_ips": len(ip_pattern)
        }

    @staticmethod
    def detect_asn_change(db: Session, user_id: str, current_asn: str) -> bool:
        """Detect if current ASN differs from user's typical ASN"""
        latest_access = DeviceAccessService.get_latest_user_access(db, user_id)

        if not latest_access or not latest_access.asn:
            return False  # No previous ASN data

        return latest_access.asn != current_asn

    @staticmethod
    def get_temporal_anomaly_score(db: Session, user_id: str, current_hour: int, current_weekday: int) -> float:
        """
        Calculate temporal anomaly score based on user's historical patterns.

        Returns:
            float: Anomaly score (0.0 = normal, 1.0 = highly anomalous)
        """
        pattern_data = DeviceAccessService.get_access_pattern_data(db, user_id, days_back=30)

        if pattern_data['total_accesses'] < 5:
            return 0.0  # Not enough data for analysis

        # Get access frequency for current time
        hourly_dist = pattern_data['hourly_distribution']
        daily_dist = pattern_data['daily_distribution']

        current_hour_count = hourly_dist.get(str(current_hour), 0)
        current_day_count = daily_dist.get(str(current_weekday), 0)

        total_accesses = pattern_data['total_accesses']

        # Calculate normalized frequencies (0.0 to 1.0)
        hour_frequency = current_hour_count / total_accesses
        day_frequency = current_day_count / total_accesses

        # Calculate anomaly score (inverse of frequency)
        # Lower frequency = higher anomaly score
        hour_anomaly = 1.0 - (hour_frequency * 24)  # Normalize for 24 hours
        day_anomaly = 1.0 - (day_frequency * 7)    # Normalize for 7 days

        # Combine scores (weighted average)
        combined_anomaly = (hour_anomaly * 0.7) + (day_anomaly * 0.3)

        # Clamp to [0.0, 1.0]
        return max(0.0, min(1.0, combined_anomaly))

    @staticmethod
    def cleanup_old_accesses(db: Session, days_to_keep: int = 90) -> int:
        """Clean up old access records for performance"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        deleted_count = db.query(DeviceAccess).filter(
            DeviceAccess.timestamp < cutoff_date
        ).delete()

        db.commit()

        # Log cleanup activity
        audit_log = AuditLog(
            event_type="access_cleanup",
            event_category="maintenance",
            severity="INFO",
            message=f"Cleaned up {deleted_count} old device access records",
            details={
                "deleted_count": deleted_count,
                "cutoff_date": cutoff_date.isoformat(),
                "days_kept": days_to_keep
            }
        )
        db.add(audit_log)
        db.commit()

        return deleted_count