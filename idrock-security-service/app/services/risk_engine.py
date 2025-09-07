import uuid
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.services.proxycheck_client import ProxyCheckClient, ProxyCheckAPIError
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
        db: Session
    ) -> IdentityVerificationResponse:
        """
        Calculate risk score based on IP reputation analysis
        
        Args:
            request: Identity verification request
            db: Database session for logging
            
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
            
            # Analyze IP reputation
            ip_analysis = await self._analyze_ip_reputation(request.ip_address)
            
            # Calculate confidence score based on IP analysis
            confidence_score = self._calculate_ip_based_score(ip_analysis)
            
            # Determine risk level
            risk_level = self._determine_risk_level(confidence_score)
            
            # Create risk factors
            risk_factors = self._create_risk_factors(ip_analysis, confidence_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(ip_analysis, risk_level, request.context.action_type.value)
            
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
            await self._store_assessment(request, response, ip_analysis, db)
            
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
        db: Session
    ):
        """
        Store risk assessment in database
        
        Args:
            request: Original request
            response: Generated response
            ip_analysis: IP analysis data
            db: Database session
        """
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
            session_data=self._serialize_session_data(request.session_data),
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