import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.services.proxycheck_client import ProxyCheckClient, ProxyCheckAPIError
from app.services.device_service import DeviceService
from app.services.device_access_service import DeviceAccessService
from app.services.travel_detection import TravelDetectionService
from app.services.hardware_validation import HardwareValidationService
from app.services.browser_validation import BrowserValidationService
from app.schemas.identity import (
    IdentityVerificationRequest,
    IdentityVerificationResponse,
    RiskFactor,
    Recommendation,
    AssessmentMetadata
)
from app.schemas.common import RiskLevel
from app.core.config import settings
from app.models.risk_assessment import RiskAssessment
from app.models.audit_log import AuditLog


class RiskEngine:
    """Simplified risk assessment engine focused on IP reputation analysis"""
    
    def __init__(self):
        self.proxycheck_client = ProxyCheckClient()
    
    async def calculate_risk_score(
        self,
        request: IdentityVerificationRequest,
        db: Session,
        enable_advanced_features: bool = True
    ) -> IdentityVerificationResponse:
        """
        Calculate comprehensive risk score including advanced security features

        Args:
            request: Identity verification request
            db: Database session for logging
            enable_advanced_features: Enable advanced security validations

        Returns:
            Complete risk assessment response
        """
        start_time = datetime.utcnow()
        request_id = f"req_{uuid.uuid4().hex[:12]}"

        try:
            # Log assessment request
            audit_log = AuditLog.log_assessment_request(
                request_id=request_id,
                user_id=request.user_id,
                ip_address=request.ip_address,
                action_type=request.context.action_type.value
            )
            db.add(audit_log)

            # Initialize analysis data
            all_risk_factors = {}
            advanced_analysis = {}

            # Core IP reputation analysis
            ip_analysis = await self._analyze_ip_reputation(request.ip_address)
            ip_score = self._calculate_ip_based_score(ip_analysis)

            # Advanced security features (if enabled)
            if enable_advanced_features:
                advanced_analysis = await self._perform_advanced_analysis(request, db)
                all_risk_factors.update(advanced_analysis.get("risk_factors", {}))

            # Calculate final confidence score
            confidence_score = self._calculate_comprehensive_score(
                ip_score,
                advanced_analysis.get("scores", {}),
                enable_advanced_features
            )

            # Determine risk level (may be overridden by advanced features)
            risk_level = self._determine_comprehensive_risk_level(
                confidence_score,
                advanced_analysis.get("override_risk", None)
            )

            # Create comprehensive risk factors
            risk_factors = self._create_comprehensive_risk_factors(
                ip_analysis,
                ip_score,
                all_risk_factors,
                enable_advanced_features
            )

            # Generate enhanced recommendations
            recommendations = self._generate_enhanced_recommendations(
                ip_analysis,
                risk_level,
                request.context.action_type.value,
                advanced_analysis.get("recommendations", [])
            )

            # Calculate processing time
            processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Create response
            response = IdentityVerificationResponse(
                confidence_score=confidence_score,
                risk_level=risk_level,
                risk_factors=risk_factors,
                recommendations=recommendations,
                metadata=AssessmentMetadata(
                    processing_time_ms=processing_time,
                    request_id=request_id
                ),
                timestamp=datetime.utcnow(),
                request_id=request_id
            )

            # Store assessment in database
            await self._store_assessment(request, response, ip_analysis, db, advanced_analysis)

            # Log assessment result
            result_audit = AuditLog.log_assessment_result(
                request_id=request_id,
                user_id=request.user_id,
                risk_level=risk_level.value,
                confidence_score=confidence_score
            )
            db.add(result_audit)
            db.commit()

            return response
            
        except Exception as e:
            # Log error
            error_audit = AuditLog.log_error(
                event_type="risk_assessment",
                error_message=str(e),
                request_id=request_id,
                user_id=request.user_id,
                details={"ip_address": request.ip_address}
            )
            db.add(error_audit)
            db.commit()
            
            # Return fallback response for service resilience
            return self._create_fallback_response(request_id, request.user_id)

    async def _perform_advanced_analysis(
        self,
        request: IdentityVerificationRequest,
        db: Session
    ) -> Dict[str, Any]:
        """
        Perform advanced security analysis including device tracking,
        travel detection, hardware validation, and browser validation.
        """
        analysis = {
            "risk_factors": {},
            "scores": {},
            "recommendations": [],
            "override_risk": None
        }

        device_fingerprint = request.session_data.device_fingerprint
        if not device_fingerprint:
            return analysis

        try:
            # Device validation and registration
            device, is_new_device = DeviceService.create_or_get_device(
                db=db,
                user_id=request.user_id,
                device_fingerprint=device_fingerprint
            )

            analysis["risk_factors"]["device_analysis"] = {
                "device_id": device.id,
                "is_new_device": is_new_device,
                "is_trusted": device.is_trusted,
                "device_age_days": (datetime.utcnow() - device.created_at).days
            }

            # New device detection
            if is_new_device:
                analysis["risk_factors"]["new_device_detected"] = {
                    "detected": True,
                    "severity": "medium",
                    "description": "Unknown device accessing user account"
                }
                analysis["scores"]["new_device_penalty"] = -20

            # Travel detection (if location data available in additional_data)
            location_data = self._extract_location_data(request)
            if location_data:
                travel_analysis = TravelDetectionService.analyze_travel_feasibility(
                    db=db,
                    user_id=request.user_id,
                    current_location=location_data,
                    current_time=datetime.utcnow()
                )

                analysis["risk_factors"]["travel_analysis"] = travel_analysis

                if not travel_analysis["is_feasible"]:
                    if travel_analysis["risk_level"] == "DENY":
                        analysis["override_risk"] = "DENY"
                        analysis["scores"]["travel_violation"] = -100
                    else:  # REVIEW
                        analysis["scores"]["travel_suspicion"] = -30

            # Temporal behavior analysis
            temporal_score = DeviceAccessService.get_temporal_anomaly_score(
                db=db,
                user_id=request.user_id,
                current_hour=datetime.utcnow().hour,
                current_weekday=datetime.utcnow().weekday()
            )

            if temporal_score > 0.7:  # High anomaly
                analysis["risk_factors"]["temporal_anomaly"] = {
                    "detected": True,
                    "severity": "medium",
                    "score": temporal_score,
                    "description": f"Access at unusual time (anomaly score: {temporal_score:.2f})"
                }
                analysis["scores"]["temporal_penalty"] = -15

            # Hardware validation (if available in additional_data)
            hardware_info = self._extract_hardware_info(request)
            if hardware_info:
                hw_validation = HardwareValidationService.validate_hardware_specs(hardware_info)
                analysis["risk_factors"]["hardware_validation"] = hw_validation["risk_factors"]

                if not hw_validation["is_valid_hardware"]:
                    analysis["scores"]["hardware_penalty"] = -25

            # Browser validation
            browser_validation = BrowserValidationService.validate_user_agent(request.user_agent)
            analysis["risk_factors"]["browser_validation"] = browser_validation["risk_factors"]

            if not browser_validation["is_legitimate"]:
                analysis["scores"]["browser_penalty"] = -30
                if "automation_detected" in browser_validation["risk_factors"]:
                    analysis["override_risk"] = "DENY"

            # Browser environment validation (if available)
            browser_env_info = self._extract_browser_environment(request)
            if browser_env_info:
                env_validation = BrowserValidationService.validate_browser_environment(browser_env_info)
                analysis["risk_factors"]["browser_environment"] = env_validation["risk_factors"]

                if not env_validation["is_real_browser"]:
                    analysis["scores"]["browser_env_penalty"] = -20

            # Record access for future analysis
            if device and location_data:
                DeviceAccessService.record_access(
                    db=db,
                    device_id=device.id,
                    ip_address=request.ip_address,
                    location_data={
                        "lat": location_data[0],
                        "lng": location_data[1],
                        "country": None,  # Could be enhanced with geocoding
                        "city": None
                    },
                    asn=None,  # Could be enhanced with ASN lookup
                    hardware_info=hardware_info,
                    browser_info={"user_agent": request.user_agent},
                    risk_factors=analysis["risk_factors"]
                )

        except Exception as e:
            # Log error but don't fail the entire assessment
            analysis["risk_factors"]["advanced_analysis_error"] = {
                "error": str(e),
                "severity": "low",
                "description": "Advanced analysis partially failed"
            }

        return analysis

    def _extract_location_data(self, request: IdentityVerificationRequest) -> Optional[Tuple[float, float]]:
        """Extract location coordinates from request additional_data"""
        try:
            additional_data = request.session_data.additional_data or {}
            lat = additional_data.get("latitude")
            lng = additional_data.get("longitude")

            if lat is not None and lng is not None:
                return (float(lat), float(lng))
        except (ValueError, TypeError):
            pass

        return None

    def _extract_hardware_info(self, request: IdentityVerificationRequest) -> Optional[Dict[str, Any]]:
        """Extract hardware information from request additional_data"""
        try:
            additional_data = request.session_data.additional_data or {}
            hardware_info = additional_data.get("hardware_info", {})

            if hardware_info:
                return hardware_info
        except Exception:
            pass

        return None

    def _extract_browser_environment(self, request: IdentityVerificationRequest) -> Optional[Dict[str, Any]]:
        """Extract browser environment information from request additional_data"""
        try:
            additional_data = request.session_data.additional_data or {}
            browser_env = additional_data.get("browser_environment", {})

            if browser_env:
                return browser_env
        except Exception:
            pass

        return None

    def _calculate_comprehensive_score(
        self,
        base_ip_score: int,
        advanced_scores: Dict[str, int],
        enable_advanced: bool
    ) -> int:
        """Calculate comprehensive risk score combining IP and advanced features"""
        if not enable_advanced:
            return base_ip_score

        total_score = base_ip_score

        # Apply advanced feature penalties/bonuses
        for score_adjustment in advanced_scores.values():
            total_score += score_adjustment

        # Ensure score is within valid range
        return max(0, min(100, total_score))

    def _determine_comprehensive_risk_level(
        self,
        confidence_score: int,
        override_risk: Optional[str]
    ) -> RiskLevel:
        """Determine risk level with potential override from advanced features"""
        if override_risk == "DENY":
            return RiskLevel.DENY

        # Use standard thresholds
        return self._determine_risk_level(confidence_score)

    def _create_comprehensive_risk_factors(
        self,
        ip_analysis: Dict[str, Any],
        ip_score: int,
        advanced_risk_factors: Dict[str, Any],
        enable_advanced: bool
    ) -> List[RiskFactor]:
        """Create comprehensive risk factor list"""
        risk_factors = []

        # IP reputation factor (always included)
        ip_details = self._format_ip_details(ip_analysis)
        risk_factors.append(
            RiskFactor(
                factor="ip_reputation",
                score=ip_score,
                weight=0.6 if enable_advanced else 1.0,
                details=ip_details,
                proxycheck_data=ip_analysis
            )
        )

        # Advanced security factors
        if enable_advanced and advanced_risk_factors:
            if "device_analysis" in advanced_risk_factors:
                device_info = advanced_risk_factors["device_analysis"]
                risk_factors.append(
                    RiskFactor(
                        factor="device_trust",
                        score=80 if device_info["is_trusted"] else 40,
                        weight=0.2,
                        details=f"Device trust status: {'trusted' if device_info['is_trusted'] else 'new/untrusted'}",
                        proxycheck_data=device_info
                    )
                )

            if "travel_analysis" in advanced_risk_factors:
                travel_info = advanced_risk_factors["travel_analysis"]
                travel_score = 20 if travel_info["is_feasible"] else 0
                risk_factors.append(
                    RiskFactor(
                        factor="travel_feasibility",
                        score=travel_score,
                        weight=0.15,
                        details=f"Travel analysis: {travel_info['analysis_details']['message']}",
                        proxycheck_data=travel_info
                    )
                )

            # Add other advanced factors as needed
            for factor_name, factor_data in advanced_risk_factors.items():
                if factor_name.endswith("_detected") and factor_data.get("detected"):
                    severity_score = {"low": 60, "medium": 40, "high": 20}.get(
                        factor_data.get("severity", "medium"), 40
                    )
                    risk_factors.append(
                        RiskFactor(
                            factor=factor_name,
                            score=severity_score,
                            weight=0.05,
                            details=factor_data.get("description", f"{factor_name} detected"),
                            proxycheck_data=factor_data
                        )
                    )

        return risk_factors

    def _generate_enhanced_recommendations(
        self,
        ip_analysis: Dict[str, Any],
        risk_level: RiskLevel,
        action_type: str,
        advanced_recommendations: List[str]
    ) -> List[Recommendation]:
        """Generate enhanced recommendations including advanced features"""
        recommendations = self._generate_recommendations(ip_analysis, risk_level, action_type)

        # Add advanced feature recommendations
        for rec_text in advanced_recommendations:
            recommendations.append(
                Recommendation(
                    action="advanced_security_measure",
                    priority="medium",
                    message=rec_text
                )
            )

        return recommendations

    async def _analyze_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Analyze IP reputation using ProxyCheck.io or mock data
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            IP reputation analysis data
        """
        try:
            if settings.proxycheck_api_key:
                # Use real ProxyCheck.io API
                return await self.proxycheck_client.check_ip(ip_address)
            else:
                # Use mock data for development/testing
                return self.proxycheck_client.get_mock_response(ip_address)
                
        except ProxyCheckAPIError as e:
            # Fallback to mock data if API fails
            print(f"ProxyCheck API error: {e}, using fallback data")
            return self.proxycheck_client.get_mock_response(ip_address)
    
    def _calculate_ip_based_score(self, ip_analysis: Dict[str, Any]) -> int:
        """
        Calculate confidence score based solely on IP reputation
        
        Args:
            ip_analysis: IP reputation analysis data
            
        Returns:
            Confidence score (0-100)
        """
        base_score = 100
        
        # ProxyCheck risk score (0-100, lower is better for ProxyCheck)
        proxycheck_risk = ip_analysis.get('risk', 0)
        base_score -= proxycheck_risk
        
        # Additional penalties for proxy/VPN/TOR
        if ip_analysis.get('proxy', '').lower() == 'yes':
            base_score -= 30
            
        # Connection type adjustments
        connection_type = ip_analysis.get('type', '').lower()
        if connection_type in ['hosting', 'datacenter']:
            base_score -= 20
        elif connection_type == 'mobile':
            base_score -= 5  # Slight penalty for mobile
        elif connection_type == 'residential':
            base_score += 5   # Bonus for residential
        
        # Country-based adjustments (simplified)
        country = ip_analysis.get('country', '').upper()
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example high-risk countries
        if country in high_risk_countries:
            base_score -= 15
        
        # Ensure score is within valid range
        return max(0, min(100, base_score))
    
    def _determine_risk_level(self, confidence_score: int) -> RiskLevel:
        """
        Determine risk level based on confidence score
        
        Args:
            confidence_score: Calculated confidence score
            
        Returns:
            Risk level enumeration
        """
        if confidence_score >= settings.allow_threshold:
            return RiskLevel.ALLOW
        elif confidence_score >= settings.review_threshold:
            return RiskLevel.REVIEW
        else:
            return RiskLevel.DENY
    
    def _create_risk_factors(self, ip_analysis: Dict[str, Any], confidence_score: int) -> List[RiskFactor]:
        """
        Create risk factor analysis from IP data
        
        Args:
            ip_analysis: IP reputation analysis data
            confidence_score: Calculated confidence score
            
        Returns:
            List of risk factors
        """
        details = self._format_ip_details(ip_analysis)
        
        return [
            RiskFactor(
                factor="ip_reputation",
                score=confidence_score,
                weight=1.0,
                details=details,
                proxycheck_data=ip_analysis
            )
        ]
    
    def _format_ip_details(self, ip_analysis: Dict[str, Any]) -> str:
        """
        Format IP analysis into human-readable details
        
        Args:
            ip_analysis: IP reputation analysis data
            
        Returns:
            Formatted details string
        """
        proxy_status = ip_analysis.get('proxy', 'unknown')
        connection_type = ip_analysis.get('type', 'unknown')
        country = ip_analysis.get('country', 'unknown')
        provider = ip_analysis.get('provider', 'unknown')
        risk_score = ip_analysis.get('risk', 0)
        
        if proxy_status == 'yes':
            return f"Proxy/VPN detected from {country} via {provider} (Risk: {risk_score})"
        elif connection_type.lower() in ['hosting', 'datacenter']:
            return f"Hosting/Datacenter connection from {country} via {provider} (Risk: {risk_score})"
        else:
            return f"Clean IP with {connection_type} connection from {country} via {provider} (Risk: {risk_score})"
    
    def _generate_recommendations(self, ip_analysis: Dict[str, Any], risk_level: RiskLevel, action_type: str) -> List[Recommendation]:
        """
        Generate risk-based recommendations
        
        Args:
            ip_analysis: IP reputation analysis data
            risk_level: Determined risk level
            action_type: Type of action being performed
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if risk_level == RiskLevel.ALLOW:
            recommendations.append(
                Recommendation(
                    action="allow_with_standard_monitoring",
                    priority="low",
                    message=f"{action_type.title()} approved - good IP reputation"
                )
            )
        elif risk_level == RiskLevel.REVIEW:
            if ip_analysis.get('proxy') == 'yes':
                recommendations.extend([
                    Recommendation(
                        action="require_additional_verification",
                        priority="medium",
                        message=f"Proxy/VPN detected - require additional verification for {action_type}"
                    ),
                    Recommendation(
                        action="enable_enhanced_monitoring",
                        priority="medium",
                        message="Enable enhanced monitoring for this session"
                    )
                ])
            else:
                recommendations.append(
                    Recommendation(
                        action="step_up_authentication",
                        priority="medium",
                        message=f"Medium risk detected - consider step-up authentication for {action_type}"
                    )
                )
        else:  # DENY
            recommendations.extend([
                Recommendation(
                    action="block_transaction",
                    priority="high",
                    message=f"High risk IP detected - block {action_type} attempt"
                ),
                Recommendation(
                    action="alert_security_team",
                    priority="high",
                    message="Alert security team for manual review"
                ),
                Recommendation(
                    action="log_for_investigation",
                    priority="high",
                    message="Log for security investigation"
                )
            ])
        
        return recommendations
    
    async def _store_assessment(
        self,
        request: IdentityVerificationRequest,
        response: IdentityVerificationResponse,
        ip_analysis: Dict[str, Any],
        db: Session,
        advanced_analysis: Optional[Dict[str, Any]] = None
    ):
        """
        Store risk assessment in database
        
        Args:
            request: Original request
            response: Generated response
            ip_analysis: IP analysis data
            db: Database session
        """
        # Merge advanced analysis data with session data
        session_data = self._serialize_session_data(request.session_data)
        if advanced_analysis:
            session_data["advanced_analysis"] = advanced_analysis

        assessment = RiskAssessment(
            request_id=response.request_id,
            user_id=request.user_id,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            action_type=request.context.action_type.value,
            transaction_amount=request.context.amount,
            confidence_score=response.confidence_score,
            risk_level=response.risk_level.value,
            risk_factors=[factor.dict() for factor in response.risk_factors],
            recommendations=[rec.dict() for rec in response.recommendations],
            session_data=session_data,
            proxycheck_response=ip_analysis,
            processing_time_ms=response.metadata.processing_time_ms,
            api_version=response.metadata.api_version
        )
        
        db.add(assessment)
    
    def _serialize_session_data(self, session_data) -> Dict[str, Any]:
        """
        Serialize session data for JSON storage, converting datetime objects to ISO strings
        
        Args:
            session_data: SessionData object
            
        Returns:
            Dictionary with JSON-serializable values
        """
        data = session_data.dict()
        
        # Convert datetime objects to ISO strings
        if 'timestamp' in data and data['timestamp']:
            data['timestamp'] = data['timestamp'].isoformat()
            
        return data

    def _create_fallback_response(self, request_id: str, user_id: str) -> IdentityVerificationResponse:
        """
        Create fallback response when risk assessment fails
        
        Args:
            request_id: Request identifier
            user_id: User identifier
            
        Returns:
            Fallback risk assessment response
        """
        return IdentityVerificationResponse(
            confidence_score=50,  # Medium confidence for fallback
            risk_level=RiskLevel.REVIEW,  # Conservative approach
            risk_factors=[
                RiskFactor(
                    factor="system_error",
                    score=50,
                    weight=1.0,
                    details="Risk assessment service temporarily unavailable - using fallback scoring",
                    proxycheck_data={"error": "service_unavailable"}
                )
            ],
            recommendations=[
                Recommendation(
                    action="manual_review_required",
                    priority="medium",
                    message="Manual review required due to service unavailability"
                )
            ],
            metadata=AssessmentMetadata(
                processing_time_ms=100,
                request_id=request_id
            ),
            timestamp=datetime.utcnow(),
            request_id=request_id
        )
    
    async def close(self):
        """Close external connections"""
        await self.proxycheck_client.close()