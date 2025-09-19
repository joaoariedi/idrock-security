from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.models.device import Device
from app.models.audit_log import AuditLog


class DeviceService:
    """Service for managing device CRUD operations and trust status"""

    @staticmethod
    def create_or_get_device(
        db: Session,
        user_id: str,
        device_fingerprint: str
    ) -> tuple[Device, bool]:
        """
        Create a new device or get existing one with unique constraint handling.

        Returns:
            tuple: (device, is_new_device)
                - device: The Device object
                - is_new_device: True if device was created, False if existed
        """
        try:
            # Attempt to create new device
            new_device = Device(
                user_id=user_id,
                device_fingerprint=device_fingerprint,
                is_trusted=False
            )
            db.add(new_device)
            db.commit()

            # Log successful device creation
            audit_log = AuditLog(
                event_type="device_created",
                event_category="security",
                severity="INFO",
                user_id=user_id,
                message=f"New device registered for user {user_id}",
                details={
                    "device_id": new_device.id,
                    "device_fingerprint": device_fingerprint[:20] + "...",  # Truncated for security
                    "trusted": new_device.is_trusted
                }
            )
            db.add(audit_log)
            db.commit()

            return new_device, True

        except IntegrityError as e:
            db.rollback()

            # Check if it's the unique constraint violation we expect
            error_str = str(e).lower()
            if "unique constraint failed" in error_str and "user_id" in error_str and "device_fingerprint" in error_str:
                # Device already exists, retrieve it
                existing_device = db.query(Device).filter(
                    Device.user_id == user_id,
                    Device.device_fingerprint == device_fingerprint
                ).first()

                if existing_device:
                    # Log device access attempt with existing device
                    audit_log = AuditLog(
                        event_type="device_accessed",
                        event_category="security",
                        severity="INFO",
                        user_id=user_id,
                        message=f"Access from known device for user {user_id}",
                        details={
                            "device_id": existing_device.id,
                            "device_fingerprint": device_fingerprint[:20] + "...",
                            "trusted": existing_device.is_trusted,
                            "device_age_days": (existing_device.updated_at - existing_device.created_at).days if existing_device.updated_at else 0
                        }
                    )
                    db.add(audit_log)
                    db.commit()

                    return existing_device, False

            # If it's a different error or device not found, re-raise
            raise e

    @staticmethod
    def get_device_by_id(db: Session, device_id: int) -> Optional[Device]:
        """Get device by ID"""
        return db.query(Device).filter(Device.id == device_id).first()

    @staticmethod
    def get_devices_by_user(db: Session, user_id: str) -> List[Device]:
        """Get all devices for a user"""
        return db.query(Device).filter(Device.user_id == user_id).order_by(Device.created_at.desc()).all()

    @staticmethod
    def get_device_by_fingerprint(db: Session, user_id: str, device_fingerprint: str) -> Optional[Device]:
        """Get device by user and fingerprint"""
        return db.query(Device).filter(
            Device.user_id == user_id,
            Device.device_fingerprint == device_fingerprint
        ).first()

    @staticmethod
    def update_trust_status(db: Session, device_id: int, is_trusted: bool, admin_user: str = None) -> Optional[Device]:
        """Update device trust status"""
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return None

        old_trust_status = device.is_trusted
        device.is_trusted = is_trusted
        db.commit()

        # Log trust status change
        audit_log = AuditLog(
            event_type="device_trust_updated",
            event_category="security",
            severity="WARN" if not is_trusted else "INFO",
            user_id=device.user_id,
            message=f"Device trust status changed: {old_trust_status} -> {is_trusted}",
            details={
                "device_id": device_id,
                "old_trusted": old_trust_status,
                "new_trusted": is_trusted,
                "admin_user": admin_user,
                "device_fingerprint": device.device_fingerprint[:20] + "..."
            }
        )
        db.add(audit_log)
        db.commit()

        return device

    @staticmethod
    def delete_device(db: Session, device_id: int) -> bool:
        """Delete a device and all its access records"""
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return False

        # Log device deletion
        audit_log = AuditLog(
            event_type="device_deleted",
            event_category="security",
            severity="WARN",
            user_id=device.user_id,
            message=f"Device deleted for user {device.user_id}",
            details={
                "device_id": device_id,
                "device_fingerprint": device.device_fingerprint[:20] + "...",
                "was_trusted": device.is_trusted,
                "access_count": len(device.accesses) if device.accesses else 0
            }
        )
        db.add(audit_log)

        # Delete device (cascades to access records)
        db.delete(device)
        db.commit()

        return True

    @staticmethod
    def count_trusted_devices(db: Session, user_id: str) -> int:
        """Count trusted devices for a user"""
        return db.query(Device).filter(
            Device.user_id == user_id,
            Device.is_trusted == True
        ).count()

    @staticmethod
    def is_device_new(db: Session, user_id: str, device_fingerprint: str) -> bool:
        """Check if this is a new device for the user"""
        existing = DeviceService.get_device_by_fingerprint(db, user_id, device_fingerprint)
        return existing is None