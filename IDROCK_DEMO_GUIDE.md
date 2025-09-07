# IDROCK Security System - Complete Demonstration Guide

This guide provides step-by-step instructions to demonstrate the complete IDROCK security system workflow, from NexShop user registration through IDROCK risk assessment and history tracking. The guide is synchronized with the automated demo script to ensure consistency between manual and automated testing.

## Automated Demo Script

For a complete automated demonstration, use the included demo script:

```bash
# Run the automated demo (recommended)
poetry run python demo-script.py
```

The automated script performs all the steps below with colorful output, comprehensive testing, and real-time progress tracking. It includes automatic service health checking, dynamic user generation, and detailed risk factor analysis. For manual testing, follow the individual steps in this guide.

## System Architecture Overview

The IDROCK system consists of two integrated services:
1. **IDROCK Security Service** (FastAPI) - Port 8000
2. **NexShop E-commerce Service** (Node.js/Express) - Port 3000

The workflow demonstrates:
- User registration in NexShop
- Login attempts with integrated IDROCK security protection
- Real-time risk assessment based on IP reputation
- Security audit trail and history tracking

---

## Prerequisites

1. Start both services using Docker Compose:
```bash
docker-compose up -d
```

2. Verify services are running:
```bash
curl http://localhost:8000/api/v1/health/
curl http://localhost:3000/health
```

---

## Demo Workflow: Complete User Journey

The demo script performs these exact steps in order. For manual testing, follow each step:

### Step 1: Service Health Check

The demo script waits for both services to be fully available (up to 60 seconds):

```bash
# Check IDROCK Security Service
curl -X GET "http://localhost:8000/api/v1/health/" \
  -H "Content-Type: application/json" | jq

# Expected Response:
# {
#   "status": "healthy",
#   "service": "IDROCK Security Service",
#   "version": "1.0.0-mvp",
#   "timestamp": "2025-09-07T10:30:00Z"
# }
```

```bash
# Check NexShop E-commerce Service
curl -X GET "http://localhost:3000/health" \
  -H "Content-Type: application/json" | jq

# Expected Response:
# {
#   "status": "healthy",
#   "service": "NexShop E-commerce Service",
#   "version": "1.0.0",
#   "uptime": 120.5,
#   "timestamp": "2025-09-07T10:30:05Z"
# }
```

### Step 2: User Registration in NexShop

The demo script generates a unique demo user for each run. For manual testing, register a user:

```bash
# Demo script uses dynamic usernames like: demouser12345678
# For manual testing, use any unique username:
curl -X POST "http://localhost:3000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "demo_user_manual",
    "email": "manual_demo@idrock.com",
    "password": "SecurePassword123",
    "first_name": "Demo",
    "last_name": "User",
    "phone": "+1-555-123-4567"
  }' | jq

# Expected Response:
# {
#   "message": "User registered successfully",
#   "user": {
#     "id": "user_12345",
#     "username": "demo_user_manual",
#     "email": "manual_demo@idrock.com",
#     "first_name": "Demo",
#     "last_name": "User"
#   },
#   "token": "jwt_token_here",
#   "expires_in": "24h"
# }
```

### Step 3: Risk Assessment Scenarios

The demo script tests three specific scenarios with detailed output. Each scenario includes:
- Complete risk assessment with confidence scoring
- Detailed risk factor analysis
- Actionable recommendations
- Processing time metrics

#### Scenario A: Low Risk (ALLOW) - Clean Residential IP

```bash
# This matches the demo script's Scenario A exactly
curl -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo_user_manual",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "session_data": {
      "timestamp": "2025-09-07T10:30:00Z",
      "device_fingerprint": "fp_clean_residential_device",
      "additional_data": {
        "browser": "Chrome",
        "screen_resolution": "1920x1080",
        "timezone": "UTC-5",
        "platform": "Windows"
      }
    },
    "context": {
      "action_type": "login",
      "additional_context": {
        "login_attempt_count": 1,
        "last_login": "2025-09-06T10:30:00Z"
      }
    }
  }' | jq

# Expected Response (Low Risk):
# {
#   "confidence_score": 85,
#   "risk_level": "ALLOW",
#   "risk_factors": [
#     {
#       "factor": "ip_reputation",
#       "score": 85,
#       "weight": 1.0,
#       "details": "Clean IP with residential connection from US via AT&T (Risk: 1)",
#       "proxycheck_data": {
#         "proxy": "no",
#         "type": "Residential",
#         "risk": 1,
#         "country": "US",
#         "provider": "AT&T"
#       }
#     }
#   ],
#   "recommendations": [
#     {
#       "action": "allow_with_standard_monitoring",
#       "priority": "low",
#       "message": "Login approved - good IP reputation"
#     }
#   ],
#   "metadata": {
#     "processing_time_ms": 125,
#     "api_version": "1.0.0-mvp",
#     "request_id": "req_abc123def456",
#     "mvp_scope": "ip_reputation_only"
#   },
#   "timestamp": "2025-09-07T10:30:15Z",
#   "request_id": "req_abc123def456"
# }
```

#### Scenario B: Medium-High Risk (VPN/Proxy) - Expected DENY for High-Risk Actions

```bash
# This matches the demo script's Scenario B exactly - VPN IP for checkout action
curl -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo_user_manual",
    "ip_address": "45.76.97.227",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "session_data": {
      "timestamp": "2025-09-07T10:35:00Z",
      "device_fingerprint": "fp_vpn_user_device",
      "additional_data": {
        "browser": "Chrome",
        "screen_resolution": "1366x768",
        "timezone": "UTC+1",
        "platform": "Linux",
        "vpn_detected": true
      }
    },
    "context": {
      "action_type": "checkout",
      "amount": 299.99,
      "additional_context": {
        "cart_value": 299.99,
        "payment_method": "credit_card",
        "items_count": 2,
        "first_purchase": false
      }
    }
  }' | jq

# Expected Response (High Risk - VPN for checkout often results in DENY):
# {
#   "confidence_score": 30,
#   "risk_level": "DENY",
#   "risk_factors": [
#     {
#       "factor": "ip_reputation",
#       "score": 45,
#       "weight": 1.0,
#       "details": "Proxy/VPN detected from Netherlands via Vultr (Risk: 55)",
#       "proxycheck_data": {
#         "proxy": "yes",
#         "type": "VPN",
#         "risk": 55,
#         "country": "NL",
#         "provider": "Vultr"
#       }
#     }
#   ],
#   "recommendations": [
#     {
#       "action": "require_additional_verification",
#       "priority": "medium",
#       "message": "Proxy/VPN detected - require additional verification for checkout"
#     },
#     {
#       "action": "enable_enhanced_monitoring",
#       "priority": "medium",
#       "message": "Enable enhanced monitoring for this session"
#     }
#   ],
#   "metadata": {
#     "processing_time_ms": 98,
#     "request_id": "req_xyz789abc123"
#   },
#   "timestamp": "2025-09-07T10:35:10Z",
#   "request_id": "req_xyz789abc123"
# }
```

#### Scenario C: High Risk (DENY) - Known Malicious/Hosting IP with Suspicious Patterns

```bash
# This matches the demo script's Scenario C exactly - Hosting IP with automation patterns
curl -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo_user_manual",
    "ip_address": "185.220.100.240",
    "user_agent": "curl/7.68.0",
    "session_data": {
      "timestamp": "2025-09-07T10:40:00Z",
      "device_fingerprint": "fp_suspicious_automation",
      "additional_data": {
        "browser": "Unknown",
        "automation_detected": true,
        "screen_resolution": "unknown",
        "suspicious_patterns": ["rapid_requests", "bot_like_behavior"]
      }
    },
    "context": {
      "action_type": "sensitive_action",
      "additional_context": {
        "action": "password_reset",
        "previous_attempts": 5,
        "time_since_last_attempt": "30_seconds"
      }
    }
  }' | jq

# Expected Response (High Risk):
# {
#   "confidence_score": 15,
#   "risk_level": "DENY",
#   "risk_factors": [
#     {
#       "factor": "ip_reputation",
#       "score": 15,
#       "weight": 1.0,
#       "details": "Hosting/Datacenter connection from Germany via Hetzner (Risk: 85)",
#       "proxycheck_data": {
#         "proxy": "yes",
#         "type": "Hosting",
#         "risk": 85,
#         "country": "DE",
#         "provider": "Hetzner"
#       }
#     }
#   ],
#   "recommendations": [
#     {
#       "action": "block_transaction",
#       "priority": "high",
#       "message": "High risk IP detected - block sensitive_action attempt"
#     },
#     {
#       "action": "alert_security_team",
#       "priority": "high",
#       "message": "Alert security team for manual review"
#     },
#     {
#       "action": "log_for_investigation",
#       "priority": "high",
#       "message": "Log for security investigation"
#     }
#   ],
#   "metadata": {
#     "processing_time_ms": 87,
#     "request_id": "req_danger123xyz"
#   },
#   "timestamp": "2025-09-07T10:40:05Z",
#   "request_id": "req_danger123xyz"
# }
```

### Step 4: Integrated Login Testing (NexShop + IDROCK)

The demo script tests integrated login scenarios that combine NexShop authentication with IDROCK risk assessment:

#### Low Risk Login (Should Succeed with Security Assessment)

```bash
# This matches the demo script's low risk login scenario
curl -X POST "http://localhost:3000/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -d '{
    "username": "demo_user_manual",
    "password": "SecurePassword123",
    "deviceFingerprint": "fp_trusted_device_chrome",
    "sessionData": {
      "browser": "Chrome",
      "screen_resolution": "1920x1080",
      "platform": "Windows",
      "timezone": "America/New_York"
    },
    "additionalData": {
      "login_source": "web_app"
    }
  }' | jq

# Expected Response (Successful Login):
# {
#   "message": "Login successful",
#   "user": {
#     "id": "user_12345",
#     "username": "demo_user",
#     "email": "demo@idrock.com"
#   },
#   "token": "jwt_token_here",
#   "expires_in": "24h",
#   "security": {
#     "risk_level": "ALLOW",
#     "confidence_score": 85,
#     "request_id": "req_login_abc123",
#     "service_available": true
#   }
# }
```

#### High Risk Login (Expected Block) - VPN IP Detection

```bash
# This matches the demo script's high risk login scenario (should be blocked)
curl -X POST "http://localhost:3000/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 45.76.97.227" \
  -d '{
    "username": "demo_user_manual",
    "password": "SecurePassword123",
    "deviceFingerprint": "fp_vpn_device",
    "sessionData": {
      "browser": "Firefox",
      "screen_resolution": "1366x768",
      "platform": "Linux",
      "timezone": "Europe/London"
    },
    "additionalData": {
      "login_source": "mobile_app"
    }
  }' | jq

# Expected Response (Login Blocked - Status 403):
# {
#   "error": "Login blocked by security policy",
#   "message": "Access denied due to security concerns",
#   "riskLevel": "DENY",
#   "requestId": "req_blocked_xyz789",
#   "securityReasons": ["High risk IP detected", "VPN/Proxy detected"],
#   "timestamp": "2025-09-07T10:45:00Z"
# }
```

### Step 5: Security History and Statistics

The demo script displays comprehensive security analytics including recent assessments, risk distribution, confidence scores, and both IDROCK and NexShop integration statistics:

#### Get Recent Assessments for Demo User

```bash
# The demo script fetches history for the specific demo user
curl -X GET "http://localhost:8000/api/v1/identity/history?limit=5&user_id=demo_user_manual" \
  -H "Content-Type: application/json" | jq

# Expected Response:
# {
#   "assessments": [
#     {
#       "id": "assessment_1",
#       "request_id": "req_abc123def456",
#       "user_id": "demo_user",
#       "ip_address": "192.168.1.100",
#       "risk_level": "ALLOW",
#       "confidence_score": 85,
#       "action_type": "login",
#       "created_at": "2025-09-07T10:30:15Z",
#       "processing_time_ms": 125
#     },
#     {
#       "id": "assessment_2",
#       "request_id": "req_xyz789abc123",
#       "user_id": "demo_user",
#       "ip_address": "45.76.97.227",
#       "risk_level": "REVIEW",
#       "confidence_score": 45,
#       "action_type": "checkout",
#       "created_at": "2025-09-07T10:35:10Z",
#       "processing_time_ms": 98
#     }
#   ],
#   "pagination": {
#     "page": 1,
#     "limit": 10,
#     "total": 2,
#     "total_pages": 1
#   },
#   "filters": {
#     "applied": ["limit", "page"],
#     "available": ["user_id", "risk_level", "action_type", "date_range"]
#   }
# }
```

#### Filter by Specific User

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?user_id=demo_user&limit=5" \
  -H "Content-Type: application/json" | jq
```

#### Filter by Risk Level

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?risk_level=REVIEW&limit=5" \
  -H "Content-Type: application/json" | jq
```

#### Filter by Action Type

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?action_type=login&limit=5" \
  -H "Content-Type: application/json" | jq
```

#### Filter by Date Range

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?start_date=2025-09-07T00:00:00Z&end_date=2025-09-07T23:59:59Z&limit=10" \
  -H "Content-Type: application/json" | jq
```

#### Get IDROCK Assessment Statistics (24 hours)

```bash
# The demo script uses 1-day statistics for current demo data
curl -X GET "http://localhost:8000/api/v1/identity/stats?days=1" \
  -H "Content-Type: application/json" | jq

# Expected Response:
# {
#   "period": {
#     "start_date": "2025-08-31T10:30:00Z",
#     "end_date": "2025-09-07T10:30:00Z",
#     "days": 7
#   },
#   "user_id": null,
#   "total_assessments": 15,
#   "risk_distribution": {
#     "ALLOW": 8,
#     "REVIEW": 5,
#     "DENY": 2
#   },
#   "average_confidence_score": 62.4,
#   "confidence_score_range": {
#     "min": 15,
#     "max": 95
#   },
#   "most_common_action": "login"
# }
```

#### Get NexShop Authentication Statistics

```bash
curl -X GET "http://localhost:3000/api/auth/stats" \
  -H "Content-Type: application/json" | jq

# Expected Response:
# {
#   "auth_stats": {
#     "total_attempts_24h": 25,
#     "successful_logins_24h": 18,
#     "blocked_attempts_24h": 2,
#     "risk_distribution_24h": {
#       "ALLOW": 18,
#       "REVIEW": 5,
#       "DENY": 2
#     }
#   },
#   "idrock_sdk_stats": {
#     "total_requests": 25,
#     "successful_requests": 23,
#     "failed_requests": 2,
#     "average_response_time_ms": 95,
#     "service_uptime": "99.2%"
#   },
#   "timestamp": "2025-09-07T10:45:00Z"
# }
```

---

## Advanced Scenarios

### Testing Different Action Types

#### Checkout Transaction Assessment

```bash
curl -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo_user",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
    "session_data": {
      "timestamp": "2025-09-07T11:00:00Z",
      "device_fingerprint": "fp_mobile_safari_iphone",
      "additional_data": {
        "browser": "Mobile Safari",
        "platform": "iOS",
        "is_mobile": true
      }
    },
    "context": {
      "action_type": "checkout",
      "amount": 1299.99,
      "additional_context": {
        "cart_items": 3,
        "payment_method": "credit_card",
        "shipping_address_new": false
      }
    }
  }' | jq
```

#### Sensitive Action Assessment

```bash
curl -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo_user",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "session_data": {
      "timestamp": "2025-09-07T11:05:00Z",
      "device_fingerprint": "fp_trusted_device",
      "additional_data": {
        "browser": "Chrome",
        "authenticated": true
      }
    },
    "context": {
      "action_type": "sensitive_action",
      "additional_context": {
        "action": "change_password",
        "triggered_by": "user_request"
      }
    }
  }' | jq
```

---

## API Documentation Access

### Interactive API Documentation (Swagger UI)

Visit the IDROCK Security Service interactive documentation:

```bash
# Open in browser
http://localhost:8000/docs

# Or fetch the OpenAPI specification
curl -X GET "http://localhost:8000/openapi.json" | jq > idrock-api-spec.json
```

---

## Troubleshooting

### Service Health Issues

```bash
# Check service status
docker-compose ps

# View service logs
docker-compose logs idrock-security
docker-compose logs nexshop-ecommerce

# Restart services if needed
docker-compose restart
```

### API Request Failures

1. **Invalid IP Address Format**: Ensure IP addresses are valid IPv4 or IPv6
2. **Missing Required Fields**: Check that all required fields are included in requests
3. **Service Unavailable**: Verify services are running and accessible

### Testing with Different IPs

For testing purposes, use these IP ranges:
- **Low Risk (ALLOW)**: 192.168.x.x, 10.x.x.x (private ranges)
- **Medium Risk (REVIEW)**: Known VPN providers (check ProxyCheck.io)
- **High Risk (DENY)**: Known hosting/datacenter IPs

### Step 6: API Documentation Access

The demo script verifies that both Swagger UI and OpenAPI specifications are available:

```bash
# Check Swagger UI availability (returns HTML)
curl -X GET "http://localhost:8000/docs" 

# Get OpenAPI specification with API details
curl -X GET "http://localhost:8000/openapi.json" | jq

# Expected OpenAPI Response includes:
# {
#   "openapi": "3.1.0",
#   "info": {
#     "title": "IDROCK Security Service API",
#     "version": "1.0.0-mvp"
#   },
#   "paths": { ... endpoint definitions ... }
# }
```

---

## Automated Demonstration Script

**RECOMMENDED**: Use the accompanying `demo-script.py` for the complete demonstration:

```bash
# Run with Poetry (recommended)
poetry run python demo-script.py

# Or with Python directly
python demo-script.py
```

The automated demo script performs all steps above with:
- **Colorful, detailed output** with success/warning/error indicators
- **Automatic service health checking** (waits up to 60 seconds)
- **Dynamic test user generation** for each run
- **Comprehensive risk scenario testing** with detailed analysis
- **Integrated login flow testing** with both success and block scenarios
- **Security history and statistics** display
- **API documentation verification**
- **Complete success/failure reporting** with troubleshooting guidance

### Demo Script Output Features:
- ✅ **Success indicators** for passed tests
- ⚠️ **Warning indicators** for expected edge cases
- ❌ **Error indicators** with detailed troubleshooting
- 🔍 **Detailed risk factor analysis** for each scenario
- 📊 **Statistics and metrics** display
- 🎉 **Summary report** with next steps

## Demo Script vs Manual Testing

**Use the demo script** (`poetry run python demo-script.py`) for:
- Complete automated testing workflow with 6 comprehensive steps
- Colorful, easy-to-follow output with success/warning/error indicators
- Automatic service health checking (waits up to 60 seconds)
- Dynamic test user generation for isolated testing
- Comprehensive success/failure reporting with troubleshooting guidance
- No manual curl command management
- Real-time progress tracking and detailed analysis

**Use manual testing** (this guide) for:
- Understanding individual API endpoints
- Custom scenario testing
- Integration debugging
- Learning the system architecture

This completes the comprehensive IDROCK system demonstration workflow showing the full integration between NexShop e-commerce and IDROCK security services with real-time risk assessment capabilities.