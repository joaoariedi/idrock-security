import httpx
import asyncio
from typing import Dict, Any, Optional
from app.core.config import settings


class ProxyCheckAPIError(Exception):
    """Custom exception for ProxyCheck API errors"""
    pass


class ProxyCheckClient:
    """Client for ProxyCheck.io API integration"""
    
    def __init__(self):
        self.api_key = settings.proxycheck_api_key
        self.api_url = settings.proxycheck_api_url
        self.timeout = settings.proxycheck_timeout
        
        # HTTP client configuration
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            headers={
                "User-Agent": f"IDROCK-Security/{settings.app_version}",
                "Accept": "application/json"
            }
        )
    
    async def check_ip(self, ip_address: str, **kwargs) -> Dict[str, Any]:
        """
        Check IP reputation using ProxyCheck.io API
        
        Args:
            ip_address: IP address to analyze
            **kwargs: Additional ProxyCheck.io parameters
            
        Returns:
            Dict containing IP reputation data
            
        Raises:
            ProxyCheckAPIError: If API request fails
        """
        try:
            # Build API endpoint URL
            endpoint = f"{self.api_url}{ip_address}"
            
            # Prepare query parameters
            params = {
                "format": "json",
                "vpn": 1,  # Check for VPN usage
                "asn": 1,  # Include ASN information
                "node": 1,  # Include node information
                "time": 1,  # Include timing information
                "inf": 0,  # Don't include inference data
                "risk": 1,  # Include risk score
                **kwargs
            }
            
            # Add API key if available
            if self.api_key:
                params["key"] = self.api_key
            
            # Make API request
            response = await self.client.get(endpoint, params=params)
            response.raise_for_status()
            
            # Parse response
            data = response.json()
            
            # Handle API errors
            if "error" in data:
                raise ProxyCheckAPIError(f"ProxyCheck API error: {data['error']}")
            
            # Extract IP data (ProxyCheck returns data under IP key)
            ip_data = data.get(ip_address, {})
            if not ip_data:
                raise ProxyCheckAPIError(f"No data returned for IP {ip_address}")
            
            # Normalize response format
            normalized_data = self._normalize_response(ip_data)
            
            return normalized_data
            
        except httpx.RequestError as e:
            raise ProxyCheckAPIError(f"HTTP request failed: {str(e)}")
        except httpx.HTTPStatusError as e:
            raise ProxyCheckAPIError(f"HTTP error {e.response.status_code}: {e.response.text}")
        except Exception as e:
            raise ProxyCheckAPIError(f"Unexpected error: {str(e)}")
    
    def _normalize_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize ProxyCheck.io response to consistent format
        
        Args:
            data: Raw ProxyCheck.io response data
            
        Returns:
            Normalized data structure
        """
        return {
            # Core fields
            "proxy": data.get("proxy", "unknown"),
            "type": data.get("type", "unknown"),
            "risk": int(data.get("risk", 0)),
            
            # Location information
            "country": data.get("country", "unknown"),
            "isocode": data.get("isocode", "unknown"),
            "region": data.get("region", "unknown"),
            "city": data.get("city", "unknown"),
            "continent": data.get("continent", "unknown"),
            
            # Network information
            "provider": data.get("provider", "unknown"),
            "organisation": data.get("organisation", "unknown"),
            "asn": data.get("asn", "unknown"),
            
            # Additional metadata
            "time_zone": data.get("timezone", "unknown"),
            "currency": {
                "code": data.get("currency", {}).get("code", "unknown"),
                "name": data.get("currency", {}).get("name", "unknown"),
                "symbol": data.get("currency", {}).get("symbol", "unknown")
            } if isinstance(data.get("currency"), dict) else {
                "code": "unknown",
                "name": "unknown", 
                "symbol": "unknown"
            },
            
            # Raw response for debugging
            "raw_response": data
        }
    
    async def check_multiple_ips(self, ip_addresses: list, **kwargs) -> Dict[str, Dict[str, Any]]:
        """
        Check multiple IP addresses concurrently
        
        Args:
            ip_addresses: List of IP addresses to check
            **kwargs: Additional ProxyCheck.io parameters
            
        Returns:
            Dict mapping IP addresses to their reputation data
        """
        tasks = [self.check_ip(ip, **kwargs) for ip in ip_addresses]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        ip_results = {}
        for ip, result in zip(ip_addresses, results):
            if isinstance(result, Exception):
                ip_results[ip] = {
                    "error": str(result),
                    "proxy": "unknown",
                    "type": "unknown",
                    "risk": 50,  # Default medium risk for errors
                    "country": "unknown"
                }
            else:
                ip_results[ip] = result
        
        return ip_results
    
    def get_mock_response(self, ip_address: str) -> Dict[str, Any]:
        """
        Get mock response for testing when API key is not configured
        
        Args:
            ip_address: IP address to mock
            
        Returns:
            Mock response data
        """
        # Simple mock based on IP patterns
        if ip_address.startswith("10.") or ip_address.startswith("192.168.") or ip_address.startswith("172."):
            # Private IP ranges
            return {
                "proxy": "no",
                "type": "Residential",
                "risk": 1,
                "country": "Private",
                "isocode": "PR",
                "provider": "Private Network",
                "organisation": "Private",
                "asn": "Private",
                "time_zone": "UTC",
                "currency": {"code": "USD", "name": "US Dollar", "symbol": "$"},
                "raw_response": {"mock": True, "ip": ip_address}
            }
        else:
            # Public IP - generic safe response
            return {
                "proxy": "no",
                "type": "Residential",
                "risk": 5,
                "country": "US",
                "isocode": "US",
                "provider": "Generic ISP",
                "organisation": "Generic Organization",
                "asn": "AS12345",
                "time_zone": "America/New_York",
                "currency": {"code": "USD", "name": "US Dollar", "symbol": "$"},
                "raw_response": {"mock": True, "ip": ip_address}
            }
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()