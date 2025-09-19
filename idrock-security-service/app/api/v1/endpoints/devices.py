from typing import List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, Path
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.database import get_db
from app.schemas.device import (
    DeviceRegistrationRequest,
    DeviceRegistrationResponse,
    DeviceAccessRequest,
    DeviceAccessResponse,
    DeviceTrustUpdateRequest,
    DeviceListResponse,
    DeviceHistoryResponse,
    DeviceInfo,
    DeviceAccessInfo
)
from app.services.device_service import DeviceService
from app.services.device_access_service import DeviceAccessService
from app.services.travel_detection import TravelDetectionService
from app.services.hardware_validation import HardwareValidationService
from app.services.browser_validation import BrowserValidationService
from app.models.device import Device
from app.models.device_access import DeviceAccess
import uuid

router = APIRouter()


@router.post("/register", response_model=DeviceRegistrationResponse)
async def register_device(
    request: DeviceRegistrationRequest,
    db: Session = Depends(get_db)
) -> DeviceRegistrationResponse:
    """
    Register a new device or get existing device for a user.

    This endpoint handles the unique constraint for user_id + device_fingerprint
    and performs initial hardware and browser validation.
    """
    request_id = f"req_device_{uuid.uuid4().hex[:12]}"

    try:
        # Create or get device with unique constraint handling
        device, is_new_device = DeviceService.create_or_get_device(
            db=db,
            user_id=request.user_id,
            device_fingerprint=request.device_fingerprint
        )

        # Perform risk assessment for new devices
        risk_assessment = {}

        if is_new_device:
            risk_assessment["new_device_detected"] = True

            # Hardware validation
            if request.hardware_info:
                hw_validation = HardwareValidationService.validate_hardware_specs(
                    request.hardware_info.dict()
                )
                risk_assessment["hardware_validation"] = {
                    "is_valid": hw_validation["is_valid_hardware"],
                    "risk_level": hw_validation["risk_level"],
                    "issues": hw_validation["validation_details"].get("issues", [])
                }

            # Browser validation
            if request.browser_info:
                browser_validation = BrowserValidationService.validate_user_agent(
                    request.browser_info.user_agent
                )
                env_validation = BrowserValidationService.validate_browser_environment(
                    request.browser_info.dict()
                )

                risk_assessment["browser_validation"] = {
                    "user_agent_legitimate": browser_validation["is_legitimate"],
                    "environment_valid": env_validation["is_real_browser"],
                    "detected_automation": browser_validation["detected_patterns"],
                    "overall_risk": "REVIEW" if (
                        browser_validation["risk_level"] == "REVIEW" or
                        env_validation["risk_level"] == "REVIEW"
                    ) else "ALLOW"
                }
        else:
            risk_assessment["new_device_detected"] = False
            risk_assessment["device_known"] = True

        # Convert device to response format
        device_info = DeviceInfo(
            device_id=device.id,
            user_id=device.user_id,
            device_fingerprint=device.device_fingerprint,
            is_trusted=device.is_trusted,
            created_at=device.created_at,
            updated_at=device.updated_at,
            access_count=len(device.accesses) if device.accesses else 0
        )

        return DeviceRegistrationResponse(
            device=device_info,
            is_new_device=is_new_device,
            risk_assessment=risk_assessment,
            timestamp=datetime.utcnow(),
            request_id=request_id
        )

    except IntegrityError as e:
        # This should not happen due to our service logic, but handle it just in case
        raise HTTPException(
            status_code=409,
            detail=f"Device registration conflict: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Device registration failed: {str(e)}"
        )


@router.post("/access", response_model=DeviceAccessResponse)
async def log_device_access(
    request: DeviceAccessRequest,
    db: Session = Depends(get_db)
) -> DeviceAccessResponse:
    """
    Log a device access and perform security analysis.

    This endpoint records device access, performs travel detection,
    and analyzes behavioral patterns.
    """
    request_id = f"req_access_{uuid.uuid4().hex[:12]}"

    try:
        # Verify device exists
        device = DeviceService.get_device_by_id(db, request.device_id)
        if not device:
            raise HTTPException(
                status_code=404,
                detail=f"Device {request.device_id} not found"
            )

        # Initialize risk factors
        risk_factors = {}
        travel_analysis = None

        # Travel detection if location data provided
        if request.location_data:
            travel_analysis = TravelDetectionService.analyze_travel_feasibility(
                db=db,
                user_id=device.user_id,
                current_location=(request.location_data.lat, request.location_data.lng),
                current_time=datetime.utcnow()
            )

            if not travel_analysis["is_feasible"]:
                risk_factors["impossible_travel"] = {
                    "detected": True,
                    "speed_kmh": travel_analysis["travel_speed_kmh"],
                    "risk_level": travel_analysis["risk_level"]
                }

        # ASN change detection
        if request.asn:
            asn_changed = DeviceAccessService.detect_asn_change(db, device.user_id, request.asn)
            risk_factors["asn_change"] = asn_changed

        # Temporal anomaly detection
        current_time = datetime.utcnow()
        temporal_anomaly = DeviceAccessService.get_temporal_anomaly_score(
            db=db,
            user_id=device.user_id,
            current_hour=current_time.hour,
            current_weekday=current_time.weekday()
        )
        risk_factors["temporal_anomaly"] = temporal_anomaly

        # Hardware validation
        if request.hardware_info:
            hw_risk_factors = HardwareValidationService.get_hardware_risk_factors(
                request.hardware_info.dict()
            )
            risk_factors.update(hw_risk_factors)

        # Browser validation
        if request.browser_info:
            browser_risk_factors = BrowserValidationService.get_browser_risk_factors(
                user_agent=request.browser_info.user_agent,
                browser_info=request.browser_info.dict()
            )
            risk_factors.update(browser_risk_factors)

        # Record access
        access = DeviceAccessService.record_access(
            db=db,
            device_id=request.device_id,
            ip_address=request.ip_address,
            location_data=request.location_data.dict() if request.location_data else None,
            asn=request.asn,
            hardware_info=request.hardware_info.dict() if request.hardware_info else None,
            browser_info=request.browser_info.dict() if request.browser_info else None,
            risk_factors=risk_factors
        )

        return DeviceAccessResponse(
            access_logged=True,
            risk_factors=risk_factors,
            travel_analysis=travel_analysis,
            timestamp=datetime.utcnow(),
            request_id=request_id
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Access logging failed: {str(e)}"
        )


@router.get("/list/{user_id}", response_model=DeviceListResponse)
async def list_user_devices(
    user_id: str = Path(..., description="User ID"),
    db: Session = Depends(get_db)
) -> DeviceListResponse:
    """Get list of devices for a user"""
    request_id = f"req_list_{uuid.uuid4().hex[:12]}"

    try:
        devices = DeviceService.get_devices_by_user(db, user_id)
        trusted_count = DeviceService.count_trusted_devices(db, user_id)

        device_list = [
            DeviceInfo(
                device_id=device.id,
                user_id=device.user_id,
                device_fingerprint=device.device_fingerprint,
                is_trusted=device.is_trusted,
                created_at=device.created_at,
                updated_at=device.updated_at,
                access_count=len(device.accesses) if device.accesses else 0
            )
            for device in devices
        ]

        return DeviceListResponse(
            devices=device_list,
            total_devices=len(device_list),
            trusted_devices=trusted_count,
            timestamp=datetime.utcnow(),
            request_id=request_id
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve devices: {str(e)}"
        )


@router.get("/history/{user_id}", response_model=DeviceHistoryResponse)
async def get_user_access_history(
    user_id: str = Path(..., description="User ID"),
    days_back: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records"),
    db: Session = Depends(get_db)
) -> DeviceHistoryResponse:
    """Get access history for all devices of a user"""
    request_id = f"req_history_{uuid.uuid4().hex[:12]}"

    try:
        accesses = DeviceAccessService.get_user_access_history(db, user_id, limit, days_back)
        pattern_data = DeviceAccessService.get_access_pattern_data(db, user_id, days_back)

        access_list = [
            DeviceAccessInfo(
                device_id=access.device_id,
                timestamp=access.timestamp,
                ip_address=access.ip_address,
                location_data=access.location_data,
                asn=access.asn,
                risk_factors=access.risk_factors
            )
            for access in accesses
        ]

        return DeviceHistoryResponse(
            accesses=access_list,
            total_accesses=len(access_list),
            analysis_period_days=days_back,
            patterns=pattern_data,
            timestamp=datetime.utcnow(),
            request_id=request_id
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve access history: {str(e)}"
        )


@router.put("/{device_id}/trust", response_model=DeviceInfo)
async def update_device_trust(
    device_id: int = Path(..., description="Device ID"),
    request: DeviceTrustUpdateRequest = ...,
    db: Session = Depends(get_db)
) -> DeviceInfo:
    """Update device trust status"""
    try:
        device = DeviceService.update_trust_status(
            db=db,
            device_id=device_id,
            is_trusted=request.is_trusted,
            admin_user=request.admin_user
        )

        if not device:
            raise HTTPException(
                status_code=404,
                detail=f"Device {device_id} not found"
            )

        return DeviceInfo(
            device_id=device.id,
            user_id=device.user_id,
            device_fingerprint=device.device_fingerprint,
            is_trusted=device.is_trusted,
            created_at=device.created_at,
            updated_at=device.updated_at,
            access_count=len(device.accesses) if device.accesses else 0
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update device trust: {str(e)}"
        )


@router.delete("/{device_id}")
async def delete_device(
    device_id: int = Path(..., description="Device ID"),
    db: Session = Depends(get_db)
) -> dict:
    """Delete a device and all its access records"""
    try:
        success = DeviceService.delete_device(db, device_id)

        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"Device {device_id} not found"
            )

        return {
            "message": f"Device {device_id} successfully deleted",
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete device: {str(e)}"
        )