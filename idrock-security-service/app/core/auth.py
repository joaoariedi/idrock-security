"""
IDROCK Security Service - Authentication Module

This module implements API key authentication for the IDROCK security service,
providing secure access control for client applications like NexShop.

Authentication is implemented using:
- HTTPBearer security scheme
- API key validation middleware
- FastAPI dependency injection for endpoint protection
"""

from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional

from app.core.config import settings


# Initialize HTTPBearer security scheme
security = HTTPBearer()


class APIKeyAuth:
    """API Key authentication handler for IDROCK security service"""

    def __init__(self):
        """Initialize the API key authentication handler"""
        self.valid_api_key = settings.idrock_api_key

    def verify_api_key(self, api_key: str) -> bool:
        """
        Verify if the provided API key is valid
        
        Args:
            api_key (str): The API key to validate
            
        Returns:
            bool: True if the API key is valid, False otherwise
        """
        if not self.valid_api_key:
            # If no API key is configured, authentication is disabled
            return True
            
        return api_key == self.valid_api_key

    async def __call__(
        self,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> str:
        """
        Authenticate the request using Bearer token (API key)
        
        Args:
            credentials: HTTP Bearer credentials from the Authorization header
            
        Returns:
            str: The validated API key
            
        Raises:
            HTTPException: 403 if authentication fails
        """
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Missing authentication credentials",
                    "message": "Authorization header with Bearer token is required",
                    "code": "MISSING_CREDENTIALS"
                },
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Extract the API key from Bearer token
        api_key = credentials.credentials

        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Invalid authentication credentials",
                    "message": "Bearer token cannot be empty",
                    "code": "EMPTY_TOKEN"
                },
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Verify the API key
        if not self.verify_api_key(api_key):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Authentication failed",
                    "message": "Invalid API key provided",
                    "code": "INVALID_API_KEY"
                },
                headers={"WWW-Authenticate": "Bearer"}
            )

        return api_key


# Create the authentication dependency
api_key_auth = APIKeyAuth()


def get_current_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """
    FastAPI dependency for API key authentication
    
    This function can be used as a dependency in FastAPI endpoints
    to require authentication. It validates the Bearer token and
    returns the authenticated API key.
    
    Usage:
        @app.get("/protected-endpoint")
        async def protected_endpoint(api_key: str = Depends(get_current_api_key)):
            # Endpoint logic here
            pass
    
    Args:
        credentials: HTTP Bearer credentials from the Authorization header
        
    Returns:
        str: The validated API key
        
    Raises:
        HTTPException: 403 if authentication fails
    """
    return api_key_auth(credentials)


async def verify_api_key_dependency(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """
    Async dependency for API key authentication
    
    Alternative async version of the authentication dependency
    for use in async endpoints.
    
    Args:
        credentials: HTTP Bearer credentials from the Authorization header
        
    Returns:
        str: The validated API key
        
    Raises:
        HTTPException: 403 if authentication fails
    """
    return await api_key_auth(credentials)