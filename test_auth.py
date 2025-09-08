#!/usr/bin/env python3
"""
Test script for API key authentication system
"""
import requests
import json
import os
from datetime import datetime, timezone

# Test configuration
IDROCK_URL = "http://localhost:8000"
TEST_API_KEY = "test-api-key-12345"
INVALID_API_KEY = "invalid-key"

def test_unauthorized_access():
    """Test that endpoints return 403 without authorization"""
    print("Testing unauthorized access...")
    
    # Test verify endpoint
    test_data = {
        "user_id": "test_user",
        "ip_address": "192.168.1.1",
        "user_agent": "Test Agent",
        "session_data": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "device_fingerprint": "test_device"
        },
        "context": {
            "action_type": "login"
        }
    }
    
    # Test without Authorization header
    print("  Testing without Authorization header...")
    response = requests.post(
        f"{IDROCK_URL}/api/v1/identity/verify",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    print(f"    Status: {response.status_code}")
    if response.status_code == 403:
        print("    ✅ Correctly blocked unauthorized request")
    else:
        print(f"    ❌ Expected 403, got {response.status_code}")
    
    # Test with invalid API key
    print("  Testing with invalid API key...")
    response = requests.post(
        f"{IDROCK_URL}/api/v1/identity/verify",
        json=test_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {INVALID_API_KEY}"
        }
    )
    print(f"    Status: {response.status_code}")
    if response.status_code == 403:
        print("    ✅ Correctly blocked invalid API key")
    else:
        print(f"    ❌ Expected 403, got {response.status_code}")

def test_authorized_access():
    """Test that endpoints work with valid API key"""
    print("Testing authorized access...")
    
    # Set environment variable for the service
    os.environ['IDROCK_API_KEY'] = TEST_API_KEY
    
    # Test data
    test_data = {
        "user_id": "test_user",
        "ip_address": "192.168.1.1",
        "user_agent": "Test Agent",
        "session_data": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "device_fingerprint": "test_device"
        },
        "context": {
            "action_type": "login"
        }
    }
    
    # Test with valid API key
    print("  Testing with valid API key...")
    response = requests.post(
        f"{IDROCK_URL}/api/v1/identity/verify",
        json=test_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_API_KEY}"
        }
    )
    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        print("    ✅ Successfully authenticated and processed request")
        result = response.json()
        print(f"    Risk Level: {result.get('risk_level', 'N/A')}")
    elif response.status_code == 403:
        print("    ❌ Authentication failed with valid key")
    else:
        print(f"    ⚠️  Unexpected status: {response.status_code}")
        print(f"    Response: {response.text[:200]}")

def test_history_endpoint():
    """Test history endpoint authentication"""
    print("Testing history endpoint...")
    
    # Test without auth
    print("  Testing history without auth...")
    response = requests.get(f"{IDROCK_URL}/api/v1/identity/history")
    print(f"    Status: {response.status_code}")
    if response.status_code == 403:
        print("    ✅ Correctly blocked unauthorized history request")
    
    # Test with valid auth
    print("  Testing history with valid auth...")
    response = requests.get(
        f"{IDROCK_URL}/api/v1/identity/history",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"}
    )
    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        print("    ✅ Successfully accessed history with authentication")
    else:
        print(f"    ⚠️  Unexpected status: {response.status_code}")

def test_stats_endpoint():
    """Test stats endpoint authentication"""
    print("Testing stats endpoint...")
    
    # Test without auth
    response = requests.get(f"{IDROCK_URL}/api/v1/identity/stats")
    print(f"  Without auth status: {response.status_code}")
    if response.status_code == 403:
        print("    ✅ Correctly blocked unauthorized stats request")
    
    # Test with valid auth
    response = requests.get(
        f"{IDROCK_URL}/api/v1/identity/stats",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"}
    )
    print(f"  With auth status: {response.status_code}")
    if response.status_code == 200:
        print("    ✅ Successfully accessed stats with authentication")
    else:
        print(f"    ⚠️  Unexpected status: {response.status_code}")

def main():
    """Run all authentication tests"""
    print("🔐 IDROCK API Key Authentication Tests")
    print("=====================================")
    
    try:
        # Check if service is running
        response = requests.get(f"{IDROCK_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"❌ Service not available at {IDROCK_URL}")
            return
        
        print("✅ IDROCK service is running")
        print()
        
        # Run tests
        test_unauthorized_access()
        print()
        test_authorized_access()
        print()
        test_history_endpoint()
        print()
        test_stats_endpoint()
        print()
        print("🎉 Authentication tests completed!")
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Could not connect to service: {e}")
        print("Make sure the IDROCK service is running on localhost:8000")

if __name__ == "__main__":
    main()