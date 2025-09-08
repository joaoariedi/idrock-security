from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.auth import verify_api_key_dependency
from app.schemas.identity import IdentityVerificationRequest, IdentityVerificationResponse
from app.schemas.history import HistoryResponse, HistoryFilters
from app.services.risk_engine import RiskEngine
from app.services.history_service import HistoryService
from app.models.risk_assessment import RiskAssessment

router = APIRouter()

# Initialize services
risk_engine = RiskEngine()
history_service = HistoryService()


@router.post("/verify", response_model=IdentityVerificationResponse)
async def verify_identity(
    request: IdentityVerificationRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key_dependency)
):
    """
    Identity verification endpoint with IP reputation analysis
    
    **Authentication Required**: This endpoint requires a valid API key in the Authorization header.
    
    This is the core MVP functionality providing real-time fraud risk assessment
    based on IP reputation analysis using ProxyCheck.io integration.
    
    **Risk Assessment Process:**
    1. Validates input parameters and IP address format
    2. Analyzes IP reputation using ProxyCheck.io API
    3. Calculates confidence score (0-100) based on IP analysis
    4. Determines risk level: ALLOW (70-100), REVIEW (30-69), DENY (0-29)
    5. Generates actionable recommendations based on risk level
    6. Stores assessment data for history and audit purposes
    
    **MVP Scope:** IP reputation analysis only. Future versions will include:
    - Behavioral analysis patterns
    - Advanced device fingerprinting
    - Machine learning risk models
    
    **Integration:** Designed for NexShop backend integration via Node.js SDK
    """
    
    try:
        # Perform risk assessment
        assessment_response = await risk_engine.calculate_risk_score(request, db)
        
        return assessment_response
        
    except Exception as e:
        # Log error and return HTTP 500
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during risk assessment",
                "message": str(e),
                "code": "ASSESSMENT_ERROR"
            }
        )


@router.get("/history", response_model=HistoryResponse)
async def get_assessment_history(
    user_id: Optional[str] = Query(None, description="Filter by specific user ID"),
    start_date: Optional[datetime] = Query(None, description="Start date for filtering (ISO8601 format)"),
    end_date: Optional[datetime] = Query(None, description="End date for filtering (ISO8601 format)"),
    risk_level: Optional[str] = Query(None, pattern="^(ALLOW|REVIEW|DENY)$", description="Filter by risk level"),
    action_type: Optional[str] = Query(None, pattern="^(login|checkout|sensitive_action)$", description="Filter by action type"),
    page: int = Query(1, ge=1, description="Page number (starts from 1)"),
    limit: int = Query(50, ge=1, le=500, description="Number of records per page (max 500)"),
    format: str = Query("json", pattern="^(json|csv)$", description="Response format"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key_dependency)
):
    """
    Retrieve security assessment history with comprehensive filtering
    
    **Authentication Required**: This endpoint requires a valid API key in the Authorization header.
    
    This endpoint provides access to historical risk assessment data with
    advanced filtering and pagination capabilities.
    
    **Query Parameters:**
    - **user_id**: Filter assessments for specific user
    - **start_date/end_date**: Date range filtering (ISO8601 format)
    - **risk_level**: Filter by ALLOW, REVIEW, or DENY
    - **action_type**: Filter by login, checkout, or sensitive_action
    - **page/limit**: Pagination controls
    - **format**: Response format (json or csv)
    
    **Use Cases:**
    - Security analytics and reporting
    - User behavior analysis
    - Compliance audit trails
    - Risk pattern identification
    
    **Response includes:**
    - Paginated assessment records
    - Applied filters summary
    - Pagination metadata
    - Request processing information
    """
    
    try:
        # Create filters object
        filters = HistoryFilters(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            risk_level=risk_level,
            action_type=action_type,
            page=page,
            limit=limit,
            format=format
        )
        
        # Get historical data
        history_response = await history_service.get_filtered_history(filters, db)
        
        return history_response
        
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid filter parameters",
                "message": str(e),
                "code": "INVALID_FILTERS"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during history retrieval",
                "message": str(e),
                "code": "HISTORY_ERROR"
            }
        )


@router.get("/stats")
async def get_assessment_stats(
    user_id: Optional[str] = Query(None, description="Get stats for specific user"),
    days: int = Query(7, ge=1, le=365, description="Number of days to analyze (max 365)"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key_dependency)
):
    """
    Get security assessment statistics
    
    **Authentication Required**: This endpoint requires a valid API key in the Authorization header.
    
    Provides summary statistics for risk assessments over a specified time period.
    Useful for security dashboards and monitoring.
    
    **Statistics included:**
    - Total assessments count
    - Risk level distribution
    - Average confidence score
    - Top risk factors
    - Assessment trends
    """
    
    try:
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Base query
        query = db.query(RiskAssessment).filter(
            RiskAssessment.created_at >= start_date,
            RiskAssessment.created_at <= end_date
        )
        
        # Filter by user if specified
        if user_id:
            query = query.filter(RiskAssessment.user_id == user_id)
        
        # Get all assessments
        assessments = query.all()
        
        # Calculate statistics
        total_assessments = len(assessments)
        
        if total_assessments == 0:
            return {
                "period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "days": days
                },
                "user_id": user_id,
                "total_assessments": 0,
                "risk_distribution": {"ALLOW": 0, "REVIEW": 0, "DENY": 0},
                "average_confidence_score": 0,
                "assessment_trends": []
            }
        
        # Risk level distribution
        risk_distribution = {}
        confidence_scores = []
        
        for assessment in assessments:
            risk_level = assessment.risk_level
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
            confidence_scores.append(assessment.confidence_score)
        
        # Average confidence score
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "user_id": user_id,
            "total_assessments": total_assessments,
            "risk_distribution": risk_distribution,
            "average_confidence_score": round(avg_confidence, 2),
            "confidence_score_range": {
                "min": min(confidence_scores),
                "max": max(confidence_scores)
            },
            "most_common_action": max(set(a.action_type for a in assessments), key=[a.action_type for a in assessments].count) if assessments else None
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during statistics calculation",
                "message": str(e),
                "code": "STATS_ERROR"
            }
        )


@router.on_event("shutdown")
async def shutdown_risk_engine():
    """Cleanup risk engine resources on shutdown"""
    await risk_engine.close()