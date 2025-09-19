import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.core.database import Base
from app.models.device import Device
from app.models.device_access import DeviceAccess


@pytest.fixture
def db_session():
    """Create in-memory SQLite database for testing"""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class TestDeviceModel:
    """Test Device model functionality and constraints"""

    def test_device_creation(self, db_session):
        """Test basic device creation"""
        device = Device(
            user_id="user123",
            device_fingerprint="fp_test_device"
        )

        db_session.add(device)
        db_session.commit()

        assert device.id is not None
        assert device.user_id == "user123"
        assert device.device_fingerprint == "fp_test_device"
        assert device.is_trusted is False
        assert device.created_at is not None
        assert device.updated_at is None

    def test_device_unique_constraint(self, db_session):
        """Test unique constraint for user_id + device_fingerprint"""
        # Create first device
        device1 = Device(
            user_id="user123",
            device_fingerprint="fp_duplicate_test"
        )
        db_session.add(device1)
        db_session.commit()

        # Attempt to create duplicate device with same user_id + fingerprint
        device2 = Device(
            user_id="user123",
            device_fingerprint="fp_duplicate_test"
        )
        db_session.add(device2)

        # Should raise IntegrityError due to unique constraint
        with pytest.raises(IntegrityError) as exc_info:
            db_session.commit()

        error_str = str(exc_info.value).lower()
        assert ("unique constraint failed" in error_str and
                "user_id" in error_str and
                "device_fingerprint" in error_str)

    def test_device_different_users_same_fingerprint(self, db_session):
        """Test that different users can have the same device fingerprint"""
        # Create device for user1
        device1 = Device(
            user_id="user1",
            device_fingerprint="fp_shared_fingerprint"
        )
        db_session.add(device1)
        db_session.commit()

        # Create device for user2 with same fingerprint - should be allowed
        device2 = Device(
            user_id="user2",
            device_fingerprint="fp_shared_fingerprint"
        )
        db_session.add(device2)
        db_session.commit()

        assert device1.id != device2.id
        assert device1.user_id != device2.user_id
        assert device1.device_fingerprint == device2.device_fingerprint

    def test_device_same_user_different_fingerprints(self, db_session):
        """Test that same user can have multiple devices with different fingerprints"""
        # Create first device for user
        device1 = Device(
            user_id="user123",
            device_fingerprint="fp_device1"
        )
        db_session.add(device1)
        db_session.commit()

        # Create second device for same user with different fingerprint
        device2 = Device(
            user_id="user123",
            device_fingerprint="fp_device2"
        )
        db_session.add(device2)
        db_session.commit()

        assert device1.id != device2.id
        assert device1.user_id == device2.user_id
        assert device1.device_fingerprint != device2.device_fingerprint

    def test_device_trust_operations(self, db_session):
        """Test device trust status operations"""
        device = Device(
            user_id="user123",
            device_fingerprint="fp_trust_test"
        )
        db_session.add(device)
        db_session.commit()

        # Initially not trusted
        assert device.is_trusted is False

        # Mark as trusted
        device.mark_trusted()
        db_session.commit()
        assert device.is_trusted is True

        # Revoke trust
        device.revoke_trust()
        db_session.commit()
        assert device.is_trusted is False

    def test_device_to_dict(self, db_session):
        """Test device dictionary conversion"""
        device = Device(
            user_id="user123",
            device_fingerprint="fp_dict_test"
        )
        db_session.add(device)
        db_session.commit()

        device_dict = device.to_dict()

        assert device_dict["device_id"] == device.id
        assert device_dict["user_id"] == "user123"
        assert device_dict["device_fingerprint"] == "fp_dict_test"
        assert device_dict["is_trusted"] is False
        assert device_dict["created_at"] is not None
        assert device_dict["access_count"] == 0

    def test_device_repr(self, db_session):
        """Test device string representation"""
        device = Device(
            user_id="user123",
            device_fingerprint="fp_repr_test_very_long_fingerprint"
        )
        db_session.add(device)
        db_session.commit()

        repr_str = repr(device)
        assert "Device" in repr_str
        assert "user123" in repr_str
        assert "fp_repr_test_very_lon" in repr_str  # Truncated fingerprint
        assert "trusted=False" in repr_str


class TestDeviceAccessModel:
    """Test DeviceAccess model functionality"""

    def test_device_access_creation(self, db_session):
        """Test basic device access creation"""
        # Create device first
        device = Device(
            user_id="user123",
            device_fingerprint="fp_access_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create device access
        access = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.100",
            location_data={"lat": -23.5505, "lng": -46.6333, "country": "BR", "city": "São Paulo"},
            asn="AS7738",
            risk_factors={"test_factor": True}
        )
        db_session.add(access)
        db_session.commit()

        assert access.device_id == device.id
        assert access.ip_address == "192.168.1.100"
        assert access.timestamp is not None
        assert access.location_data["country"] == "BR"
        assert access.asn == "AS7738"

    def test_device_access_relationship(self, db_session):
        """Test relationship between Device and DeviceAccess"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_relationship_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create multiple accesses
        access1 = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.100"
        )
        access2 = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.101"
        )

        db_session.add_all([access1, access2])
        db_session.commit()

        # Test relationship
        assert len(device.accesses) == 2
        assert access1.device == device
        assert access2.device == device

    def test_device_access_composite_primary_key(self, db_session):
        """Test composite primary key (device_id + timestamp)"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_composite_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create first access
        timestamp1 = datetime(2025, 9, 19, 10, 30, 0)
        access1 = DeviceAccess(
            device_id=device.id,
            timestamp=timestamp1,
            ip_address="192.168.1.100"
        )
        db_session.add(access1)
        db_session.commit()

        # Create second access with different timestamp - should work
        timestamp2 = datetime(2025, 9, 19, 10, 31, 0)
        access2 = DeviceAccess(
            device_id=device.id,
            timestamp=timestamp2,
            ip_address="192.168.1.101"
        )
        db_session.add(access2)
        db_session.commit()

        # Attempt to create access with same device_id + timestamp - should fail
        access3 = DeviceAccess(
            device_id=device.id,
            timestamp=timestamp1,  # Same timestamp as access1
            ip_address="192.168.1.102"
        )
        db_session.add(access3)

        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_device_access_location_properties(self, db_session):
        """Test location-related properties and methods"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_location_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create access with location data
        access = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.100",
            location_data={
                "lat": -23.5505,
                "lng": -46.6333,
                "country": "BR",
                "city": "São Paulo"
            }
        )
        db_session.add(access)
        db_session.commit()

        # Test properties
        assert access.latitude == -23.5505
        assert access.longitude == -46.6333
        assert access.country == "BR"
        assert access.city == "São Paulo"
        assert access.has_location() is True
        assert access.get_coordinates() == (-23.5505, -46.6333)

    def test_device_access_no_location(self, db_session):
        """Test access without location data"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_no_location_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create access without location data
        access = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.100"
        )
        db_session.add(access)
        db_session.commit()

        # Test properties
        assert access.latitude is None
        assert access.longitude is None
        assert access.country is None
        assert access.city is None
        assert access.has_location() is False
        assert access.get_coordinates() is None

    def test_device_access_to_dict(self, db_session):
        """Test device access dictionary conversion"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_dict_access_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create access
        access = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.100",
            location_data={"lat": -23.5505, "lng": -46.6333},
            asn="AS7738",
            risk_factors={"test": True}
        )
        db_session.add(access)
        db_session.commit()

        access_dict = access.to_dict()

        assert access_dict["device_id"] == device.id
        assert access_dict["ip_address"] == "192.168.1.100"
        assert access_dict["location_data"]["lat"] == -23.5505
        assert access_dict["asn"] == "AS7738"
        assert access_dict["risk_factors"]["test"] is True
        assert access_dict["timestamp"] is not None

    def test_device_cascade_delete(self, db_session):
        """Test that deleting device cascades to access records"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_cascade_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create access records
        access1 = DeviceAccess(device_id=device.id, ip_address="192.168.1.100")
        access2 = DeviceAccess(device_id=device.id, ip_address="192.168.1.101")
        db_session.add_all([access1, access2])
        db_session.commit()

        device_id = device.id

        # Verify access records exist
        access_count = db_session.query(DeviceAccess).filter(
            DeviceAccess.device_id == device_id
        ).count()
        assert access_count == 2

        # Delete device
        db_session.delete(device)
        db_session.commit()

        # Verify access records are deleted
        access_count = db_session.query(DeviceAccess).filter(
            DeviceAccess.device_id == device_id
        ).count()
        assert access_count == 0

    def test_device_access_repr(self, db_session):
        """Test device access string representation"""
        # Create device
        device = Device(
            user_id="user123",
            device_fingerprint="fp_repr_access_test"
        )
        db_session.add(device)
        db_session.commit()

        # Create access
        access = DeviceAccess(
            device_id=device.id,
            ip_address="192.168.1.100"
        )
        db_session.add(access)
        db_session.commit()

        repr_str = repr(access)
        assert "DeviceAccess" in repr_str
        assert str(device.id) in repr_str
        assert "192.168.1.100" in repr_str