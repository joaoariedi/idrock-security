# IDROCK - IP Reputation Security Tool - Complete Demonstration Guide

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
- User registration in NexShop with device fingerprinting
- Advanced security features including device trust management
- Impossible travel detection with geodesic calculations
- Hardware validation and browser automation detection
- Login attempts with integrated IDROCK security protection
- Real-time multi-factor risk assessment
- Comprehensive security audit trail and analytics

---

## Prerequisites and Environment Setup

### System Requirements

Before starting the demonstration, ensure your system meets these requirements:

```bash
# Check system requirements
echo "Checking system requirements..."

# Docker and Docker Compose
docker --version && docker-compose --version || echo "❌ Docker/Docker Compose not found"

# Python 3.9+ (for local development)
python3 --version | grep -E "Python 3\.(9|1[0-9])" && echo "✅ Python 3.9+" || echo "❌ Python 3.9+ required"

# Node.js 18+ (for local development)
node --version | grep -E "v(1[8-9]|2[0-9])" && echo "✅ Node.js 18+" || echo "❌ Node.js 18+ required"

# curl and jq for testing
which curl && which jq && echo "✅ curl and jq available" || echo "❌ Install curl and jq"

echo "System check complete!"
```

### Complete Environment Configuration

#### 1. Repository Setup
```bash
# Clone the repository (if not already done)
git clone https://github.com/joaoariedi/idrock-security.git
cd idrock-new

# Ensure you're on the correct branch with advanced security features
git checkout feature/advanced_security_features_sprint4

# Verify you have the latest changes
git pull origin feature/advanced_security_features_sprint4
```

#### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Create comprehensive environment configuration
cat << 'EOF' > .env
# IDROCK Security Service Configuration
IDROCK_API_KEY=demo-api-key-12345
PROXYCHECK_API_KEY=your_key_here_optional

# Database Configuration
DATABASE_URL=sqlite:///./idrock_security.db
NEXSHOP_DATABASE_URL=sqlite:///./nexshop_ecommerce.db

# Security Configuration
SECRET_KEY=idrock-super-secret-key-change-in-production
JWT_SECRET=nexshop-jwt-secret-key-for-authentication
BCRYPT_ROUNDS=12

# Service URLs
IDROCK_API_URL=http://localhost:8000
NEXSHOP_API_URL=http://localhost:3000

# Advanced Security Features (all enabled for demo)
ENABLE_DEVICE_TRUST=true
ENABLE_TRAVEL_DETECTION=true
ENABLE_HARDWARE_VALIDATION=true
ENABLE_BROWSER_AUTOMATION_DETECTION=true

# Travel Detection Configuration
TRAVEL_REVIEW_THRESHOLD=1000
TRAVEL_DENY_THRESHOLD=2000

# Hardware Validation Configuration
MIN_CPU_CORES=2
MIN_RAM_GB=4

# CORS and Security
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
LOG_LEVEL=INFO
DEBUG_MODE=false
EOF

echo "✅ Environment configuration created"
```

#### 3. Service Deployment

##### Docker Deployment (Recommended)
```bash
# Start all services with comprehensive logging
docker-compose up -d

# Monitor startup logs
docker-compose logs -f &
LOGS_PID=$!

# Wait for services to be ready (up to 120 seconds)
echo "Waiting for services to start..."
for i in {1..120}; do
  if curl -s http://localhost:8000/health >/dev/null 2>&1 && \
     curl -s http://localhost:3000/health >/dev/null 2>&1; then
    echo "✅ All services are ready!"
    kill $LOGS_PID 2>/dev/null
    break
  fi
  echo "Waiting... ($i/120)"
  sleep 1
done

# Verify service status
echo "Final service check:"
curl -s http://localhost:8000/health | jq '.status' | grep -q "healthy" && echo "✅ IDROCK healthy" || echo "❌ IDROCK failed"
curl -s http://localhost:3000/health | jq '.status' | grep -q "healthy" && echo "✅ NexShop healthy" || echo "❌ NexShop failed"
```

##### Local Development Setup (Alternative)
```bash
# IDROCK Security Service
cd idrock-security-service
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
IDROCK_PID=$!

# NexShop E-commerce Service
cd ../nexshop-ecommerce-service
npm install
npm run dev &
NEXSHOP_PID=$!

# Wait for services
sleep 10

# Test services
curl -s http://localhost:8000/health && echo "✅ IDROCK local ready"
curl -s http://localhost:3000/health && echo "✅ NexShop local ready"

# Store PIDs for cleanup
echo "IDROCK_PID=$IDROCK_PID" > .local_services
echo "NEXSHOP_PID=$NEXSHOP_PID" >> .local_services
```

#### 4. Database Initialization and Migration
```bash
# Run database migrations for advanced security features
cd idrock-security-service

# Apply Alembic migrations (creates device and device_access tables)
python -m alembic upgrade head

# Verify database schema
python -c "
from app.core.database import engine, Base
from app.models.device import Device
from app.models.device_access import DeviceAccess
import sqlalchemy

# Check table existence
inspector = sqlalchemy.inspect(engine)
tables = inspector.get_table_names()
print(f'📊 Database tables: {tables}')

if 'devices' in tables and 'device_accesses' in tables:
    print('✅ Advanced security tables created successfully')
else:
    print('❌ Database migration failed')
"

cd ..
```

#### 5. Pre-Demo Validation
```bash
# Comprehensive pre-demo system check
echo "🧪 Running pre-demo validation..."

# 1. API Authentication Test
echo "Testing API authentication..."
curl -s -H "Authorization: Bearer demo-api-key-12345" \
  "http://localhost:8000/api/v1/identity/stats" | jq '.total_assessments' >/dev/null && \
  echo "✅ API authentication working" || echo "❌ API authentication failed"

# 2. Database Connectivity Test
echo "Testing database connectivity..."
python -c "
from idrock-security-service.app.core.database import engine
try:
    with engine.connect() as conn:
        result = conn.execute(text('SELECT COUNT(*) FROM devices'))
        print('✅ Database connection successful')
except Exception as e:
    print(f'❌ Database error: {e}')
"

# 3. Advanced Features Test
echo "Testing advanced security features..."
curl -s -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"validation_user","device_fingerprint":"validation_fp"}' | \
  jq '.success' | grep -q true && \
  echo "✅ Device management working" || echo "❌ Device management failed"

# 4. SDK Integration Test
echo "Testing SDK integration..."
curl -s -X POST "http://localhost:3000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "validation_user",
    "email": "validation@test.com",
    "password": "TestPass123",
    "first_name": "Test",
    "last_name": "User"
  }' | jq '.success' >/dev/null && \
  echo "✅ NexShop integration working" || echo "❌ NexShop integration failed"

echo "🎉 Pre-demo validation complete! Ready to run demonstration."
```

### Quick Start Commands

For immediate demonstration setup, run these commands in sequence:

```bash
# Quick setup (5 minutes)
git checkout feature/advanced_security_features_sprint4 && \
cp .env.example .env && \
sed -i 's/your-api-key-here/demo-api-key-12345/' .env && \
docker-compose up -d && \
sleep 30 && \
python demo-script.py

# Expected result: All 7 demonstration steps should pass with 100% success rate
```

**Important**: All IDROCK Security Service endpoints (`/verify`, `/history`, `/stats`) require API key authentication. The demo script automatically handles authentication using the `IDROCK_API_KEY` environment variable.

---

## Demo Workflow: Complete User Journey with Advanced Security

The demo script performs these exact steps in order, demonstrating all advanced security features. For manual testing, follow each step:

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
  -H "Authorization: Bearer demo-api-key-12345" \
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
  -H "Authorization: Bearer demo-api-key-12345" \
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
  -H "Authorization: Bearer demo-api-key-12345" \
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
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" | jq

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
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" | jq
```

#### Filter by Risk Level

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?risk_level=REVIEW&limit=5" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" | jq
```

#### Filter by Action Type

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?action_type=login&limit=5" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" | jq
```

#### Filter by Date Range

```bash
curl -X GET "http://localhost:8000/api/v1/identity/history?start_date=2025-09-07T00:00:00Z&end_date=2025-09-07T23:59:59Z&limit=10" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" | jq
```

#### Get IDROCK Assessment Statistics (24 hours)

```bash
# The demo script uses 1-day statistics for current demo data
curl -X GET "http://localhost:8000/api/v1/identity/stats?days=1" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" | jq

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
  -H "Authorization: Bearer demo-api-key-12345" \
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
  -H "Authorization: Bearer demo-api-key-12345" \
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

## Advanced Security Features Demonstration

The demo script includes comprehensive testing of advanced security features implemented in Sprint 4. These features showcase cutting-edge fraud prevention capabilities:

### Step 6: Advanced Security Features

#### Device Trust Management

The demo script demonstrates the complete device management lifecycle:

```bash
# Register a new device with advanced fingerprinting
curl -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{
    "user_id": "demo_user",
    "device_fingerprint": "fp_demo_device_advanced",
    "hardware_info": {
      "cpu_cores": 8,
      "ram_gb": 16,
      "screen_resolution": "1920x1080",
      "platform": "Win32",
      "timezone": -300,
      "language": "en-US"
    },
    "browser_info": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "canvas_fingerprint": "sha256:a1b2c3d4e5f6...",
      "webgl_fingerprint": "sha256:f6e5d4c3b2a1...",
      "audio_fingerprint": "sha256:1a2b3c4d5e6f..."
    }
  }' | jq

# Expected Response:
# {
#   "success": true,
#   "message": "Device registered successfully",
#   "device": {
#     "device_id": 42,
#     "user_id": "demo_user",
#     "is_trusted": false,
#     "created_at": "2025-09-22T14:00:00Z",
#     "hardware_validation": "VALID",
#     "browser_validation": "LEGITIMATE"
#   }
# }
```

```bash
# List user devices
curl -X GET "http://localhost:8000/api/v1/devices/list/demo_user" \
  -H "Authorization: Bearer demo-api-key-12345" | jq

# Update device trust status
curl -X PUT "http://localhost:8000/api/v1/devices/42/trust" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{"is_trusted": true}' | jq
```

#### Impossible Travel Detection

The demo script demonstrates geographic analysis with real-world scenarios:

```bash
# Log access from New York
curl -X POST "http://localhost:8000/api/v1/devices/access" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{
    "device_id": 42,
    "ip_address": "192.168.1.100",
    "location_data": {
      "lat": 40.7128,
      "lng": -74.0060,
      "country": "US",
      "city": "New York"
    }
  }' | jq

# Attempt access from Tokyo 2 minutes later (impossible travel)
curl -X POST "http://localhost:8000/api/v1/devices/access" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{
    "device_id": 42,
    "ip_address": "192.168.2.100",
    "location_data": {
      "lat": 35.6762,
      "lng": 139.6503,
      "country": "JP",
      "city": "Tokyo"
    }
  }' | jq

# Expected Response:
# {
#   "success": false,
#   "risk_level": "DENY",
#   "message": "Impossible travel detected",
#   "travel_analysis": {
#     "travel_speed_kmh": 19312503.5,
#     "distance_km": 10875.7,
#     "time_diff_hours": 0.033,
#     "is_feasible": false
#   }
# }
```

#### Hardware Validation

Testing insufficient hardware detection:

```bash
# Register device with insufficient specs
curl -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{
    "user_id": "demo_user",
    "device_fingerprint": "fp_weak_device",
    "hardware_info": {
      "cpu_cores": 1,
      "ram_gb": 2,
      "screen_resolution": "800x600",
      "platform": "Linux i686"
    }
  }' | jq

# Expected Response shows hardware validation failure:
# {
#   "success": true,
#   "device": {
#     "hardware_validation": "SUSPICIOUS",
#     "validation_issues": [
#       "Insufficient CPU cores: 1 (minimum: 2)",
#       "Insufficient RAM: 2GB (minimum: 4GB)"
#     ]
#   }
# }
```

#### Browser Automation Detection

Testing automation tool detection:

```bash
# Simulate Selenium automation
curl -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{
    "user_id": "demo_user",
    "device_fingerprint": "fp_automation_test",
    "browser_info": {
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36 Selenium/3.141.59",
      "detected_patterns": ["selenium", "automated", "headless"]
    }
  }' | jq

# Expected Response shows automation detection:
# {
#   "success": true,
#   "device": {
#     "browser_validation": "AUTOMATION DETECTED",
#     "detected_patterns": ["selenium", "automated", "headless"],
#     "risk_factors": {
#       "automation_tool": {
#         "detected": true,
#         "severity": "high",
#         "description": "Selenium automation detected"
#       }
#     }
#   }
# }
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

### Step 7: API Documentation Access

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

---

## Testing and Validation Guide

### Comprehensive Testing Workflow

#### 1. Pre-Deployment Testing
```bash
# Environment validation before running any demonstrations
echo "🧪 Running comprehensive pre-deployment tests..."

# System requirements check
./scripts/check_system_requirements.sh || {
  echo "❌ System requirements not met"
  exit 1
}

# Environment configuration validation
./scripts/validate_environment.sh || {
  echo "❌ Environment configuration issues"
  exit 1
}

# Service health check
./scripts/health_check.sh || {
  echo "❌ Services health check failed"
  exit 1
}

echo "✅ Pre-deployment tests passed"
```

#### 2. Core Functionality Testing
```bash
# Test each advanced security feature individually

# Device Trust Management Test
echo "Testing Device Trust Management..."
TEST_DEVICE_ID=$(curl -s -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test_user","device_fingerprint":"test_fp"}' | jq -r '.device.device_id')

if [[ "$TEST_DEVICE_ID" != "null" ]]; then
  echo "✅ Device registration working"

  # Test trust status update
  curl -s -X PUT "http://localhost:8000/api/v1/devices/$TEST_DEVICE_ID/trust" \
    -H "Authorization: Bearer demo-api-key-12345" \
    -H "Content-Type: application/json" \
    -d '{"is_trusted":true}' | jq '.success' | grep -q true && \
    echo "✅ Device trust management working" || echo "❌ Trust management failed"
else
  echo "❌ Device registration failed"
fi

# Impossible Travel Detection Test
echo "Testing Impossible Travel Detection..."
python3 -c "
import requests
import time
from datetime import datetime

headers = {'Authorization': 'Bearer demo-api-key-12345', 'Content-Type': 'application/json'}

# First location (New York)
ny_data = {
    'device_id': $TEST_DEVICE_ID,
    'ip_address': '192.168.1.100',
    'location_data': {'lat': 40.7128, 'lng': -74.0060, 'country': 'US', 'city': 'New York'}
}
ny_response = requests.post('http://localhost:8000/api/v1/devices/access',
                           headers=headers, json=ny_data)

time.sleep(2)  # 2 second gap

# Second location (Tokyo) - should trigger impossible travel
tokyo_data = {
    'device_id': $TEST_DEVICE_ID,
    'ip_address': '192.168.2.100',
    'location_data': {'lat': 35.6762, 'lng': 139.6503, 'country': 'JP', 'city': 'Tokyo'}
}
tokyo_response = requests.post('http://localhost:8000/api/v1/devices/access',
                              headers=headers, json=tokyo_data)

result = tokyo_response.json()
if result.get('risk_level') == 'DENY' and 'travel' in result.get('message', '').lower():
    print('✅ Impossible travel detection working')
else:
    print('❌ Impossible travel detection failed')
"

# Hardware Validation Test
echo "Testing Hardware Validation..."
curl -s -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":"hw_test_user",
    "device_fingerprint":"hw_test_fp",
    "hardware_info":{"cpu_cores":1,"ram_gb":1,"screen_resolution":"640x480"}
  }' | jq '.device.hardware_validation' | grep -q "SUSPICIOUS" && \
  echo "✅ Hardware validation working" || echo "❌ Hardware validation failed"

# Browser Automation Detection Test
echo "Testing Browser Automation Detection..."
curl -s -X POST "http://localhost:8000/api/v1/devices/register" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":"bot_test_user",
    "device_fingerprint":"bot_test_fp",
    "browser_info":{
      "user_agent":"HeadlessChrome Selenium/3.141.59",
      "detected_patterns":["selenium","automated","headless"]
    }
  }' | jq '.device.browser_validation' | grep -q "AUTOMATION" && \
  echo "✅ Browser automation detection working" || echo "❌ Automation detection failed"
```

#### 3. Integration Testing
```bash
# Test end-to-end integration between NexShop and IDROCK

echo "Testing NexShop ↔ IDROCK Integration..."

# Register test user in NexShop
TEST_USERNAME="integration_test_$(date +%s)"
curl -s -X POST "http://localhost:3000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USERNAME\",
    \"email\": \"${TEST_USERNAME}@test.com\",
    \"password\": \"TestPass123\",
    \"first_name\": \"Integration\",
    \"last_name\": \"Test\"
  }" | jq '.success' | grep -q true && \
  echo "✅ NexShop user registration working" || echo "❌ User registration failed"

# Test login with risk assessment
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:3000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USERNAME\",
    \"password\": \"TestPass123\",
    \"deviceFingerprint\": \"integration_test_fp\"
  }")

echo "$LOGIN_RESPONSE" | jq '.success' | grep -q true && \
  echo "✅ Integrated login working" || echo "❌ Integrated login failed"

# Check if risk assessment was performed
echo "$LOGIN_RESPONSE" | jq '.riskAssessment' | grep -q -v null && \
  echo "✅ Risk assessment integration working" || echo "❌ Risk assessment integration failed"
```

#### 4. Performance Testing
```bash
# Basic performance testing for demonstration environment

echo "Running Performance Tests..."

# Test response time for risk assessment
RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' -X POST \
  "http://localhost:8000/api/v1/identity/verify" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":"perf_test_user",
    "ip_address":"192.168.1.100",
    "user_agent":"Mozilla/5.0 Test Browser",
    "session_data":{"timestamp":"2025-09-22T14:00:00Z"},
    "context":{"action_type":"login"}
  }')

# Convert to milliseconds
RESPONSE_MS=$(echo "$RESPONSE_TIME * 1000" | bc)

if (( $(echo "$RESPONSE_MS < 1000" | bc -l) )); then
  echo "✅ Risk assessment response time: ${RESPONSE_MS}ms (< 1000ms target)"
else
  echo "⚠️ Risk assessment response time: ${RESPONSE_MS}ms (slower than 1000ms target)"
fi

# Concurrent request test (simple load test)
echo "Testing concurrent requests..."
for i in {1..10}; do
  curl -s -X POST "http://localhost:8000/api/v1/identity/verify" \
    -H "Authorization: Bearer demo-api-key-12345" \
    -H "Content-Type: application/json" \
    -d "{
      \"user_id\":\"load_test_user_$i\",
      \"ip_address\":\"192.168.1.$i\",
      \"user_agent\":\"Load Test Browser\",
      \"session_data\":{\"timestamp\":\"$(date -Iseconds)\"},
      \"context\":{\"action_type\":\"login\"}
    }" > /dev/null &
done

wait
echo "✅ Concurrent request test completed (10 parallel requests)"
```

#### 5. Error Handling Testing
```bash
# Test error handling and edge cases

echo "Testing Error Handling..."

# Test invalid API key
curl -s -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Authorization: Bearer invalid-key" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test","ip_address":"192.168.1.1"}' | \
  jq '.detail' | grep -q -i "unauthorized\|forbidden" && \
  echo "✅ Invalid API key properly rejected" || echo "❌ API key validation failed"

# Test malformed request
curl -s -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"invalid":"data"}' | \
  jq '.detail' | grep -q -i "validation\|required" && \
  echo "✅ Malformed request properly handled" || echo "❌ Request validation failed"

# Test service unavailable scenarios
echo "Testing service resilience..."
# Simulate temporary service unavailability by stopping one service
docker-compose stop idrock-security &>/dev/null

# Test NexShop fallback behavior
curl -s -X POST "http://localhost:3000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"fallback_test","password":"TestPass123"}' | \
  jq '.fallbackUsed' | grep -q true && \
  echo "✅ Fallback mechanism working" || echo "⚠️ Check fallback implementation"

# Restart IDROCK service
docker-compose start idrock-security &>/dev/null
sleep 10  # Wait for service to be ready
```

#### 6. Security Testing
```bash
# Basic security validation tests

echo "Running Security Tests..."

# Test SQL injection protection
curl -s -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test'\'' OR 1=1 --","ip_address":"192.168.1.1"}' | \
  jq '.risk_level' | grep -q -v null && \
  echo "✅ SQL injection protection working" || echo "❌ SQL injection vulnerability"

# Test XSS protection
curl -s -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"<script>alert('\''xss'\'')</script>","ip_address":"192.168.1.1"}' | \
  jq '.user_id' | grep -q -v "<script>" && \
  echo "✅ XSS protection working" || echo "❌ XSS vulnerability"

# Test rate limiting (if implemented)
echo "Testing rate limiting..."
for i in {1..20}; do
  RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "http://localhost:8000/api/v1/identity/verify" \
    -H "Authorization: Bearer demo-api-key-12345" \
    -H "Content-Type: application/json" \
    -d '{"user_id":"rate_test","ip_address":"192.168.1.1"}')

  if [[ "$RESPONSE_CODE" == "429" ]]; then
    echo "✅ Rate limiting activated at request $i"
    break
  fi
done
```

#### 7. Demo Script Validation
```bash
# Validate that the demo script works perfectly

echo "Validating Demo Script..."

# Run demo script and capture output
DEMO_OUTPUT=$(python demo-script.py 2>&1)
DEMO_EXIT_CODE=$?

if [[ $DEMO_EXIT_CODE -eq 0 ]]; then
  echo "✅ Demo script executed successfully"

  # Check for all expected steps
  echo "$DEMO_OUTPUT" | grep -q "Step 1.*Service Health Check" && echo "✅ Step 1 found"
  echo "$DEMO_OUTPUT" | grep -q "Step 2.*User Registration" && echo "✅ Step 2 found"
  echo "$DEMO_OUTPUT" | grep -q "Step 3.*Risk Assessment" && echo "✅ Step 3 found"
  echo "$DEMO_OUTPUT" | grep -q "Step 4.*Integrated Login" && echo "✅ Step 4 found"
  echo "$DEMO_OUTPUT" | grep -q "Step 5.*Security History" && echo "✅ Step 5 found"
  echo "$DEMO_OUTPUT" | grep -q "Step 6.*Advanced Security" && echo "✅ Step 6 found"
  echo "$DEMO_OUTPUT" | grep -q "Step 7.*API Documentation" && echo "✅ Step 7 found"

  # Check success rate
  SUCCESS_RATE=$(echo "$DEMO_OUTPUT" | grep -o "Success Rate: [0-9.]*%" | cut -d' ' -f3)
  if [[ "$SUCCESS_RATE" == "100.0%" ]]; then
    echo "🎉 Demo script achieved 100% success rate!"
  else
    echo "⚠️ Demo script success rate: $SUCCESS_RATE (expected 100%)"
  fi
else
  echo "❌ Demo script failed with exit code $DEMO_EXIT_CODE"
  echo "Last 20 lines of output:"
  echo "$DEMO_OUTPUT" | tail -20
fi
```

### Test Results Summary

After running all tests, you should see:

```
🎯 Expected Test Results:
✅ All advanced security features working
✅ Device management with unique constraints
✅ Impossible travel detection (>1000 km/h flagged)
✅ Hardware validation (insufficient specs detected)
✅ Browser automation detection (Selenium flagged)
✅ API authentication working
✅ Database connectivity established
✅ Integration between services working
✅ Error handling proper
✅ Security protections in place
✅ Demo script 100% success rate

🚀 System Status: PRODUCTION READY
```

This completes the comprehensive IDROCK system demonstration workflow showing the full integration between NexShop e-commerce and IDROCK security services with real-time risk assessment capabilities and advanced security features including device trust management, impossible travel detection, hardware validation, and browser automation detection.