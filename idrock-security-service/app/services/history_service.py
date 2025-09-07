import uuid
import math
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from app.models.risk_assessment import RiskAssessment
from app.schemas.history import (
    HistoryFilters,
    HistoryResponse,
    AssessmentRecord,
    PaginationInfo,
    AppliedFilters,
    HistoryResponseMetadata
)


class HistoryService:
    """Service for managing assessment history retrieval"""
    
    async def get_filtered_history(self, filters: HistoryFilters, db: Session) -> HistoryResponse:
        """
        Retrieve filtered assessment history with pagination
        
        Args:
            filters: Filter parameters for history query
            db: Database session
            
        Returns:
            Paginated history response
        """
        start_time = datetime.utcnow()
        request_id = f"hist_{uuid.uuid4().hex[:12]}"
        
        # Build base query
        query = db.query(RiskAssessment)
        
        # Apply filters
        query = self._apply_filters(query, filters)
        
        # Get total count for pagination
        total_records = query.count()
        
        # Calculate pagination
        total_pages = math.ceil(total_records / filters.limit)
        offset = (filters.page - 1) * filters.limit
        
        # Apply pagination and ordering
        assessments = query.order_by(desc(RiskAssessment.created_at)).offset(offset).limit(filters.limit).all()
        
        # Convert to response format
        assessment_records = [self._convert_to_record(assessment) for assessment in assessments]
        
        # Create pagination info
        pagination = PaginationInfo(
            current_page=filters.page,
            total_pages=max(1, total_pages),
            total_records=total_records,
            records_per_page=filters.limit,
            has_next=filters.page < total_pages,
            has_previous=filters.page > 1
        )
        
        # Create applied filters summary
        applied_filters = self._create_filters_summary(filters)
        
        # Calculate response time
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Create metadata
        metadata = HistoryResponseMetadata(
            request_id=request_id,
            response_time_ms=response_time
        )
        
        return HistoryResponse(
            data=assessment_records,
            pagination=pagination,
            filters_applied=applied_filters,
            metadata=metadata,
            timestamp=datetime.utcnow(),
            request_id=request_id
        )
    
    def _apply_filters(self, query, filters: HistoryFilters):
        """
        Apply filters to the SQLAlchemy query
        
        Args:
            query: Base SQLAlchemy query
            filters: Filter parameters
            
        Returns:
            Filtered query
        """
        # User ID filter
        if filters.user_id:
            query = query.filter(RiskAssessment.user_id == filters.user_id)
        
        # Date range filters
        if filters.start_date:
            query = query.filter(RiskAssessment.created_at >= filters.start_date)
        
        if filters.end_date:
            query = query.filter(RiskAssessment.created_at <= filters.end_date)
        
        # Risk level filter
        if filters.risk_level:
            query = query.filter(RiskAssessment.risk_level == filters.risk_level)
        
        # Action type filter
        if filters.action_type:
            query = query.filter(RiskAssessment.action_type == filters.action_type)
        
        return query
    
    def _convert_to_record(self, assessment: RiskAssessment) -> AssessmentRecord:
        """
        Convert database model to API response record
        
        Args:
            assessment: Database assessment model
            
        Returns:
            API assessment record
        """
        return AssessmentRecord(
            assessment_id=assessment.request_id,
            user_id=assessment.user_id,
            timestamp=assessment.created_at,
            ip_address=assessment.ip_address,
            confidence_score=assessment.confidence_score,
            risk_level=assessment.risk_level,
            action_type=assessment.action_type,
            risk_factors=assessment.risk_factors or [],
            device_fingerprint=self._extract_device_fingerprint(assessment.session_data),
            user_agent=assessment.user_agent,
            processing_time_ms=assessment.processing_time_ms,
            transaction_amount=assessment.transaction_amount
        )
    
    def _extract_device_fingerprint(self, session_data: dict) -> Optional[str]:
        """
        Extract device fingerprint from session data
        
        Args:
            session_data: Session data dictionary
            
        Returns:
            Device fingerprint if available
        """
        if session_data and isinstance(session_data, dict):
            return session_data.get('device_fingerprint')
        return None
    
    def _create_filters_summary(self, filters: HistoryFilters) -> AppliedFilters:
        """
        Create summary of applied filters
        
        Args:
            filters: Filter parameters
            
        Returns:
            Applied filters summary
        """
        date_range = None
        if filters.start_date and filters.end_date:
            date_range = f"{filters.start_date.strftime('%Y-%m-%d')} to {filters.end_date.strftime('%Y-%m-%d')}"
        elif filters.start_date:
            date_range = f"from {filters.start_date.strftime('%Y-%m-%d')}"
        elif filters.end_date:
            date_range = f"until {filters.end_date.strftime('%Y-%m-%d')}"
        
        return AppliedFilters(
            user_id=filters.user_id,
            date_range=date_range,
            risk_level=filters.risk_level,
            action_type=filters.action_type
        )
    
    async def get_user_assessment_summary(self, user_id: str, days: int, db: Session) -> dict:
        """
        Get assessment summary for a specific user
        
        Args:
            user_id: User identifier
            days: Number of days to look back
            db: Database session
            
        Returns:
            User assessment summary
        """
        end_date = datetime.utcnow()
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = start_date - (datetime.timedelta(days=days - 1))
        
        assessments = db.query(RiskAssessment).filter(
            and_(
                RiskAssessment.user_id == user_id,
                RiskAssessment.created_at >= start_date,
                RiskAssessment.created_at <= end_date
            )
        ).order_by(desc(RiskAssessment.created_at)).all()
        
        if not assessments:
            return {
                "user_id": user_id,
                "period_days": days,
                "total_assessments": 0,
                "risk_distribution": {"ALLOW": 0, "REVIEW": 0, "DENY": 0},
                "average_confidence": 0,
                "last_assessment": None,
                "unique_ips": 0,
                "most_common_action": None
            }
        
        # Calculate statistics
        total_assessments = len(assessments)
        risk_distribution = {"ALLOW": 0, "REVIEW": 0, "DENY": 0}
        confidence_scores = []
        unique_ips = set()
        action_types = []
        
        for assessment in assessments:
            risk_distribution[assessment.risk_level] += 1
            confidence_scores.append(assessment.confidence_score)
            unique_ips.add(assessment.ip_address)
            action_types.append(assessment.action_type)
        
        average_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        most_common_action = max(set(action_types), key=action_types.count) if action_types else None
        
        return {
            "user_id": user_id,
            "period_days": days,
            "total_assessments": total_assessments,
            "risk_distribution": risk_distribution,
            "average_confidence": round(average_confidence, 2),
            "last_assessment": assessments[0].created_at.isoformat(),
            "unique_ips": len(unique_ips),
            "most_common_action": most_common_action,
            "confidence_trend": {
                "recent_average": round(sum(a.confidence_score for a in assessments[:5]) / min(5, len(assessments)), 2),
                "overall_average": round(average_confidence, 2)
            }
        }