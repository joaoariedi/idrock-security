from typing import Tuple, Optional, Dict, Any
from datetime import datetime
from geopy.distance import geodesic
from sqlalchemy.orm import Session
from app.models.device_access import DeviceAccess
from app.services.device_access_service import DeviceAccessService


class TravelDetectionService:
    """Service for detecting impossible travel patterns based on geographic coordinates"""

    # Thresholds for travel speed analysis (km/h)
    SPEED_THRESHOLD_REVIEW = 1000  # Trigger REVIEW for speeds > 1000 km/h
    SPEED_THRESHOLD_DENY = 2000    # Trigger DENY for speeds > 2000 km/h

    @staticmethod
    def calculate_travel_speed(
        previous_location: Tuple[float, float],
        current_location: Tuple[float, float],
        previous_time: datetime,
        current_time: datetime
    ) -> float:
        """
        Calculate travel speed between two geographic locations.

        Args:
            previous_location: (latitude, longitude) of previous access
            current_location: (latitude, longitude) of current access
            previous_time: Timestamp of previous access
            current_time: Timestamp of current access

        Returns:
            float: Travel speed in km/h
        """
        # Calculate distance using geodesic (great circle) distance
        distance_km = geodesic(previous_location, current_location).kilometers

        # Calculate time difference in hours
        time_diff = current_time - previous_time
        time_hours = time_diff.total_seconds() / 3600

        # Avoid division by zero
        if time_hours <= 0:
            return float('inf')  # Simultaneous access = impossible travel

        return distance_km / time_hours

    @staticmethod
    def analyze_travel_feasibility(
        db: Session,
        user_id: str,
        current_location: Tuple[float, float],
        current_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Analyze travel feasibility for a user based on their latest access.

        Args:
            db: Database session
            user_id: User identifier
            current_location: Current access location (lat, lng)
            current_time: Current access time (defaults to now)

        Returns:
            Dict containing analysis results:
            {
                "is_feasible": bool,
                "risk_level": str,  # "ALLOW", "REVIEW", "DENY"
                "travel_speed_kmh": float,
                "distance_km": float,
                "time_diff_hours": float,
                "previous_location": dict,
                "analysis_details": dict
            }
        """
        if current_time is None:
            current_time = datetime.utcnow()

        # Get the latest access for the user
        latest_access = DeviceAccessService.get_latest_user_access(db, user_id)

        # If no previous access or no location data, allow
        if not latest_access or not latest_access.has_location():
            return {
                "is_feasible": True,
                "risk_level": "ALLOW",
                "travel_speed_kmh": 0.0,
                "distance_km": 0.0,
                "time_diff_hours": 0.0,
                "previous_location": None,
                "analysis_details": {
                    "reason": "no_previous_location_data",
                    "message": "No previous location data available for comparison"
                }
            }

        previous_coords = latest_access.get_coordinates()
        if not previous_coords:
            return {
                "is_feasible": True,
                "risk_level": "ALLOW",
                "travel_speed_kmh": 0.0,
                "distance_km": 0.0,
                "time_diff_hours": 0.0,
                "previous_location": None,
                "analysis_details": {
                    "reason": "invalid_previous_coordinates",
                    "message": "Previous location coordinates are invalid"
                }
            }

        # Calculate travel metrics
        distance_km = geodesic(previous_coords, current_location).kilometers
        time_diff = current_time - latest_access.timestamp
        time_hours = time_diff.total_seconds() / 3600

        # Handle edge cases
        if time_hours <= 0:
            return {
                "is_feasible": False,
                "risk_level": "DENY",
                "travel_speed_kmh": float('inf'),
                "distance_km": distance_km,
                "time_diff_hours": time_hours,
                "previous_location": {
                    "lat": previous_coords[0],
                    "lng": previous_coords[1],
                    "timestamp": latest_access.timestamp.isoformat()
                },
                "analysis_details": {
                    "reason": "simultaneous_access",
                    "message": "Access attempt at same time or before previous access"
                }
            }

        travel_speed = distance_km / time_hours

        # Determine risk level based on speed thresholds
        if travel_speed > TravelDetectionService.SPEED_THRESHOLD_DENY:
            risk_level = "DENY"
            is_feasible = False
        elif travel_speed > TravelDetectionService.SPEED_THRESHOLD_REVIEW:
            risk_level = "REVIEW"
            is_feasible = False
        else:
            risk_level = "ALLOW"
            is_feasible = True

        return {
            "is_feasible": is_feasible,
            "risk_level": risk_level,
            "travel_speed_kmh": round(travel_speed, 2),
            "distance_km": round(distance_km, 2),
            "time_diff_hours": round(time_hours, 2),
            "previous_location": {
                "lat": previous_coords[0],
                "lng": previous_coords[1],
                "country": latest_access.country,
                "city": latest_access.city,
                "timestamp": latest_access.timestamp.isoformat()
            },
            "analysis_details": {
                "reason": "travel_speed_analysis",
                "message": f"Travel speed of {travel_speed:.2f} km/h is {'acceptable' if is_feasible else 'suspicious'}",
                "thresholds": {
                    "review_threshold": TravelDetectionService.SPEED_THRESHOLD_REVIEW,
                    "deny_threshold": TravelDetectionService.SPEED_THRESHOLD_DENY
                }
            }
        }

    @staticmethod
    def validate_coordinates(lat: float, lng: float) -> bool:
        """Validate geographic coordinates"""
        return -90 <= lat <= 90 and -180 <= lng <= 180

    @staticmethod
    def get_travel_risk_factors(
        db: Session,
        user_id: str,
        current_location: Tuple[float, float],
        current_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive travel risk factors for integration with risk engine.

        Returns risk factors that can be integrated into the main risk assessment.
        """
        analysis = TravelDetectionService.analyze_travel_feasibility(
            db, user_id, current_location, current_time
        )

        risk_factors = {
            "travel_analysis": {
                "enabled": True,
                "travel_speed_kmh": analysis["travel_speed_kmh"],
                "distance_km": analysis["distance_km"],
                "time_diff_hours": analysis["time_diff_hours"],
                "is_feasible": analysis["is_feasible"],
                "risk_level": analysis["risk_level"]
            }
        }

        # Add specific risk indicators
        if analysis["travel_speed_kmh"] > TravelDetectionService.SPEED_THRESHOLD_DENY:
            risk_factors["impossible_travel"] = {
                "detected": True,
                "severity": "high",
                "description": f"Impossible travel detected: {analysis['travel_speed_kmh']} km/h"
            }
        elif analysis["travel_speed_kmh"] > TravelDetectionService.SPEED_THRESHOLD_REVIEW:
            risk_factors["suspicious_travel"] = {
                "detected": True,
                "severity": "medium",
                "description": f"Suspicious travel speed: {analysis['travel_speed_kmh']} km/h"
            }

        # Add geographic context
        if analysis["previous_location"]:
            risk_factors["geographic_context"] = {
                "previous_country": analysis["previous_location"].get("country"),
                "cross_border": analysis["distance_km"] > 100,  # Rough cross-border threshold
                "intercontinental": analysis["distance_km"] > 5000  # Rough intercontinental threshold
            }

        return risk_factors

    @staticmethod
    def update_speed_thresholds(review_threshold: float, deny_threshold: float) -> bool:
        """
        Update speed thresholds for travel detection.

        Args:
            review_threshold: Speed in km/h to trigger REVIEW
            deny_threshold: Speed in km/h to trigger DENY

        Returns:
            bool: True if thresholds were updated successfully
        """
        if review_threshold <= 0 or deny_threshold <= 0 or review_threshold >= deny_threshold:
            return False

        TravelDetectionService.SPEED_THRESHOLD_REVIEW = review_threshold
        TravelDetectionService.SPEED_THRESHOLD_DENY = deny_threshold
        return True