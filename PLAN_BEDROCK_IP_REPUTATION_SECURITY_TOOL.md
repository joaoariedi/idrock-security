# IDROCK - IP Reputation Security Tool
## Comprehensive Project Plan

### Project Overview

**Project Name**: IDROCK - Sistema de Análise de Reputação de Acesso para Determinação de Risco de Fraude  
**Target Client**: NexShop (E-commerce Platform)  
**Development Team**: João Carlos Ariedi Filho, Raphael Hideyuki Uematsu, Tiago Elusardo Marques, Lucas Mazzaferro Dias  
**Framework**: Secure Development Best Practices  
**Date**: 2025  

### Objectives

The primary objective is to develop a comprehensive IP reputation security tool that:
- Provides real-time fraud risk assessment during login, checkout, and sensitive operations
- Integrates seamlessly with e-commerce platforms through JavaScript SDK and Node.js SDK
- Minimizes user friction while maximizing security effectiveness
- Delivers confidence scores (0-100) through a REST API endpoint
- Implements adaptive risk thresholds (ALLOW, REVIEW, DENY)

### Technical Architecture

#### High-Level Architecture - Two Independent Services with SDK Integration
```
┌─────────────────────────────────────────────────────────────────────────┐
│                           IDROCK SECURITY TOOL                        │
│                         (Independent Service)                          │
└─────────────────────────────────────────────────────────────────────────┘
                    ┌──────────────────┐    ┌─────────────────┐
                    │                  │    │                 │
                    │   FastAPI        │◄──►│  ProxyCheck.io  │
                    │   Backend API    │    │  External API   │
                    │   + Swagger Docs │    │                 │
                    └──────────────────┘    └─────────────────┘
                             ▲                        
                             │ SDK HTTP API Calls         
                             ▼                        
┌─────────────────────────────────────────────────────────────────────────┐
│                           NEXSHOP E-COMMERCE                           │
│                         (Independent Service)                          │
└─────────────────────────────────────────────────────────────────────────┘
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│                 │    │                  │    │                  │
│   React         │◄──►│   Node.js        │◄──►│   SQLite         │
│   Frontend      │    │   Express.js     │    │   Database       │
│   + JS SDK      │    │   Backend        │    │   (E-commerce)   │
│                 │    │   + Node.js SDK  │    │                  │
└─────────────────┘    └──────────────────┘    └──────────────────┘
         ▲                       ▲                             
         │                       │                      
         ▼                       ▼                             
┌─────────────────┐    ┌──────────────────┐              
│                 │    │                  │              
│  IDROCK         │    │  IDROCK          │              
│  JavaScript SDK │    │  Node.js SDK     │              
│  (Frontend)     │    │  (Backend)       │              
└─────────────────┘    └──────────────────┘              
         ▲                       ▲                      
         │ Generates data for    │ Makes API calls to           
         │ NexShop Backend       │ IDROCK FastAPI         
         └───────────────────────┘                      

INTEGRATION FLOW:
1. NexShop Frontend → integrates IDROCK JavaScript SDK → generates necessary information → sends to NexShop Backend
2. NexShop Backend (Node.js/Express) → integrates IDROCK Node.js SDK → makes API calls to IDROCK FastAPI service
3. IDROCK FastAPI Service → calls ProxyCheck.io external service → processes IP reputation → returns response to NexShop Backend
4. NexShop Backend → receives IDROCK response → processes business logic → responds to NexShop Frontend

IDROCK API Endpoints:
- /identity/verify (Core MVP functionality - IP reputation only)
- /identity/history (Assessment history)
- /health (System status)
- /docs (Interactive API documentation)
- /redoc (Alternative API documentation)
```

#### Technology Stack

**IDROCK Security Service**
- FastAPI (Python 3.9+) - Main API framework
- Pydantic for data validation and API schemas
- SQLAlchemy for database ORM
- Alembic for database migrations
- SQLite for security data storage
- Asyncio for concurrent request handling
- Automatic OpenAPI/Swagger documentation at /docs endpoint

**NexShop E-commerce Service**
- Node.js (v18+) - Backend runtime
- Express.js - Web framework
- Sequelize - SQLite ORM for e-commerce data
- React (v18+) - Frontend framework
- SQLite - E-commerce database (separate from IDROCK)
- Axios - HTTP client for IDROCK API communication
- Jest - Testing framework

**Service Communication**
- HTTP REST API calls between services
- JSON request/response format
- Direct service-to-service communication (no message queues)

**External Integrations (MVP)**
- ProxyCheck.io API for IP reputation analysis only

**Development Tools**
- Docker for containerization
- Postman/Insomnia for API testing
- Manual deployment procedures

**Development & Testing Tools**
- pytest for comprehensive API testing
- FastAPI TestClient for endpoint testing
- Postman/Insomnia for API development and testing
- Docker for containerization and local development (both services)
- Manual deployment and testing procedures

### API Specifications

#### POST /identity/verify Endpoint

**Request Format (MVP - IP Reputation Only)**:
```json
{
  "user_id": "string",
  "ip_address": "string",
  "user_agent": "string",
  "session_data": {
    "timestamp": "ISO8601"
  },
  "context": {
    "action_type": "login|checkout|sensitive_action",
    "amount": "number (optional for financial transactions)"
  }
}
```

**Response Format (MVP - IP Reputation Only)**:
```json
{
  "confidence_score": 85,
  "risk_level": "ALLOW|REVIEW|DENY",
  "risk_factors": [
    {
      "factor": "ip_reputation",
      "score": 85,
      "weight": 1.0,
      "details": "Clean IP with good reputation from ProxyCheck.io",
      "proxycheck_data": {
        "proxy": "no",
        "type": "Residential",
        "risk": 1,
        "country": "US",
        "provider": "AT&T"
      }
    }
  ],
  "recommendations": [
    {
      "action": "allow_with_standard_monitoring",
      "priority": "low",
      "message": "Transaction approved - good IP reputation"
    }
  ],
  "metadata": {
    "processing_time_ms": 85,
    "api_version": "1.0.0-mvp",
    "request_id": "uuid4",
    "mvp_scope": "ip_reputation_only"
  }
}
```

#### Additional API Endpoints

**GET /identity/history**
- Retrieve security assessment history with comprehensive filtering
- Query parameters:
  - `user_id`: Filter by specific user
  - `start_date`: ISO8601 datetime for range start
  - `end_date`: ISO8601 datetime for range end
  - `risk_level`: Filter by ALLOW, REVIEW, DENY
  - `action_type`: Filter by login, checkout, sensitive_action
  - `page`: Page number for pagination (default: 1)
  - `limit`: Records per page (default: 50, max: 500)
  - `format`: Response format (json, csv)
- Response includes assessment details, risk factors, and metadata
- Supports sorting by timestamp, confidence_score, risk_level

**GET /health**
- API health check endpoint
- System status and version information
- Database connectivity status

**GET /docs**
- Interactive API documentation (Swagger UI)
- Complete endpoint specifications
- Request/response examples and schemas

#### GET /identity/history Response Format

```json
{
  "data": [
    {
      "assessment_id": "uuid4",
      "user_id": "string",
      "timestamp": "2025-09-07T10:30:00Z",
      "ip_address": "192.168.1.100",
      "confidence_score": 85,
      "risk_level": "ALLOW",
      "action_type": "login",
      "risk_factors": [
        {
          "factor": "ip_reputation",
          "score": 90,
          "weight": 0.3,
          "details": "Clean IP with good reputation"
        }
      ],
      "device_fingerprint": "string",
      "user_agent": "string",
      "processing_time_ms": 145
    }
  ],
  "pagination": {
    "current_page": 1,
    "total_pages": 10,
    "total_records": 500,
    "records_per_page": 50,
    "has_next": true,
    "has_previous": false
  },
  "filters_applied": {
    "user_id": "optional_string",
    "date_range": "2025-09-01 to 2025-09-07",
    "risk_level": "ALLOW",
    "action_type": "login"
  },
  "metadata": {
    "request_id": "uuid4",
    "response_time_ms": 25,
    "api_version": "1.0.0"
  }
}
```

### Risk Scoring System (MVP - Simplified)

#### Confidence Score Calculation (0-100) - IP Reputation Only

The confidence score is calculated using a simplified algorithm focused on IP reputation:

```
Confidence Score = IP Reputation Score (ProxyCheck.io analysis)

MVP Scope:
- IP Reputation (weight: 1.0) - Single factor analysis
- ProxyCheck.io integration for comprehensive IP analysis
- Simplified risk calculation for faster response times
- Future phases will add additional analysis factors
```

#### Risk Thresholds

**ALLOW (Confidence Score: 70-100)**
- Low risk transactions
- Automatic approval
- Minimal additional verification
- Standard monitoring

**REVIEW (Confidence Score: 30-69)**
- Medium risk transactions
- Additional verification required
- Enhanced monitoring
- Possible manual review
- Step-up authentication

**DENY (Confidence Score: 0-29)**
- High risk transactions
- Block transaction
- Alert security team
- Log for investigation
- Possible account lock

#### Risk Factors Analysis (MVP - IP Reputation Only)

**IP Reputation Analysis (ProxyCheck.io)**
```json
{
  "proxy": "yes|no",
  "type": "Residential|Business|Hosting|Mobile",
  "risk": "0-100 (integer)",
  "country": "ISO country code",
  "provider": "ISP provider name",
  "asn": "ASN number",
  "continent": "Continent name",
  "time_zone": "Time zone",
  "organisation": "Organization name",
  "isocode": "ISO country code",
  "currency": {
    "code": "Currency code",
    "name": "Currency name",
    "symbol": "Currency symbol"
  }
}
```

**MVP Scope Note**: Complex behavioral analysis, device fingerprinting, geographic analysis, and bot detection are removed from MVP and will be implemented in future phases.


### FastAPI Backend Architecture - Two Independent Services

#### IDROCK Security Tool Service Structure

```
idrock-security-service/
├── app/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── endpoints/
│   │   │   │   ├── identity.py        # Core verification & history endpoints
│   │   │   │   ├── health.py          # System health and status
│   │   │   │   └── docs.py            # Custom documentation endpoints
│   │   │   └── api.py                 # API router aggregation
│   │   └── dependencies.py            # Shared API dependencies
│   ├── core/
│   │   ├── config.py                  # Application configuration
│   │   ├── security.py                # API security and authentication
│   │   ├── database.py                # SQLite connection and session management
│   │   └── openapi.py                 # Custom OpenAPI/Swagger configuration
│   ├── models/
│   │   ├── risk_assessment.py         # Risk assessment data model (SQLite)
│   │   └── audit_log.py               # Audit and compliance logging
│   ├── schemas/
│   │   ├── identity.py                # Identity verification request/response schemas
│   │   ├── history.py                 # History endpoint schemas with filtering
│   │   ├── health.py                  # Health check response schemas
│   │   └── common.py                  # Shared Pydantic models
│   ├── services/
│   │   ├── risk_engine.py             # Simplified risk assessment (IP only)
│   │   ├── proxycheck_client.py       # ProxyCheck.io API integration
│   │   └── history_service.py         # Assessment history management
│   └── utils/
│       ├── helpers.py                 # Utility functions
│       ├── validators.py              # Input validation utilities
│       ├── formatters.py              # Response formatting utilities
│       └── pagination.py              # Pagination utilities for history endpoint
├── migrations/                        # Alembic database migrations
├── tests/                            # Test suite
└── Dockerfile                        # Container configuration

#### NexShop E-commerce Service Structure (Node.js/Express)

```
nexshop-ecommerce-service/
├── src/
│   ├── controllers/
│   │   ├── authController.js         # Authentication controllers
│   │   ├── productController.js      # Product management controllers
│   │   ├── orderController.js        # Order processing controllers
│   │   └── securityController.js     # IDROCK integration endpoints
│   ├── middleware/
│   │   ├── auth.js                   # Authentication middleware
│   │   ├── validation.js             # Request validation
│   │   └── security.js               # Security middleware with IDROCK
│   ├── models/
│   │   ├── User.js                   # User model (Sequelize/SQLite)
│   │   ├── Product.js                # Product model
│   │   ├── Order.js                  # Order model
│   │   └── SecurityLog.js            # Security event logging
│   ├── routes/
│   │   ├── auth.js                   # Authentication routes
│   │   ├── products.js               # Product routes
│   │   ├── orders.js                 # Order routes
│   │   └── security.js               # Security/IDROCK integration routes
│   ├── services/
│   │   ├── authService.js            # Authentication service with IDROCK
│   │   ├── orderService.js           # Order processing with security checks
│   │   └── bedrockClient.js          # IDROCK API client service
│   ├── config/
│   │   ├── database.js               # SQLite configuration (Sequelize)
│   │   ├── app.js                    # Express app configuration
│   │   └── bedrock.js                # IDROCK API configuration
│   └── public/
│       ├── js/
│       │   └── bedrock-sdk.js        # JavaScript SDK
│       └── css/
├── client/                           # React Frontend
│   ├── src/
│   │   ├── components/               # React components
│   │   ├── pages/                    # Page components
│   │   ├── hooks/                    # Custom hooks including IDROCK
│   │   ├── services/                 # Frontend services
│   │   └── utils/
│   ├── package.json
│   └── webpack.config.js
├── migrations/                       # Database migrations (Sequelize)
├── tests/                           # Test suite (Jest)
├── package.json                     # Node.js dependencies
├── server.js                        # Express server entry point
└── Dockerfile                       # Container configuration
```

#### Risk Engine Implementation (MVP - Simplified)

```python
class RiskEngine:
    def __init__(self):
        # MVP: Single factor analysis with IP reputation only
        self.proxycheck_client = ProxyCheckClient()
    
    async def calculate_risk_score(self, assessment_data: AssessmentData) -> RiskScore:
        # MVP: Only analyze IP reputation using ProxyCheck.io
        ip_analysis = await self._analyze_ip_reputation(assessment_data.ip_address)
        confidence_score = self._calculate_ip_based_score(ip_analysis)
        risk_level = self._determine_risk_level(confidence_score)
        
        return RiskScore(
            confidence_score=confidence_score,
            risk_level=risk_level,
            factors=[
                {
                    "factor": "ip_reputation",
                    "score": confidence_score,
                    "weight": 1.0,
                    "details": self._format_ip_details(ip_analysis),
                    "proxycheck_data": ip_analysis
                }
            ],
            recommendations=self._generate_ip_recommendations(ip_analysis, risk_level)
        )
    
    async def _analyze_ip_reputation(self, ip_address: str) -> dict:
        """Analyze IP using ProxyCheck.io API"""
        return await self.proxycheck_client.check_ip(ip_address)
    
    def _calculate_ip_based_score(self, ip_analysis: dict) -> int:
        """Calculate confidence score based solely on IP reputation"""
        base_score = 100
        
        # ProxyCheck risk score (0-100, lower is better)
        proxycheck_risk = ip_analysis.get('risk', 0)
        base_score -= proxycheck_risk
        
        # Additional penalties for proxy/VPN/TOR
        if ip_analysis.get('proxy') == 'yes':
            base_score -= 30
        
        # Connection type adjustments
        connection_type = ip_analysis.get('type', '').lower()
        if connection_type in ['hosting', 'datacenter']:
            base_score -= 20
        elif connection_type == 'mobile':
            base_score -= 5  # Slight penalty for mobile
        
        return max(0, min(100, base_score))
```

### Service Communication Patterns with SDK Integration

#### SDK-Mediated Communication Architecture

The IDROCK system uses a dual-SDK approach to ensure proper service separation while maintaining secure communication:

**Communication Flow Overview:**
1. **Frontend (React)** uses **IDROCK JavaScript SDK** to collect device/session data
2. **JavaScript SDK** sends data to **NexShop Backend** (NOT directly to IDROCK API)
3. **NexShop Backend** uses **IDROCK Node.js SDK** to communicate with **IDROCK FastAPI**
4. **IDROCK FastAPI** processes request and calls **ProxyCheck.io** external service
5. Response flows back: **IDROCK FastAPI** → **Node.js SDK** → **NexShop Backend** → **React Frontend**

**IDROCK API Client Integration (Node.js)**
```javascript
// idrockClient.js - IDROCK API client service  
class IDRockAPIClient {
    constructor(config) {
        this.baseURL = config.idrockApiUrl; // e.g., http://localhost:8000
        this.apiKey = config.apiKey;
        this.timeout = config.timeout || 5000;
    }

    async verifyIdentity(userData) {
        const payload = {
            user_id: userData.userId,
            ip_address: userData.ipAddress,
            user_agent: userData.userAgent,
            session_data: {
                timestamp: new Date().toISOString()
            },
            context: {
                action_type: userData.actionType, // 'login' | 'checkout' | 'sensitive_action'
                amount: userData.amount // for checkout operations
            }
        };

        try {
            const response = await axios.post(`${this.baseURL}/identity/verify`, payload, {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                timeout: this.timeout
            });
            
            return response.data;
        } catch (error) {
            // Handle IDROCK API errors gracefully
            console.error('IDROCK API Error:', error.message);
            throw new IDRockAPIError(error);
        }
    }

    async getAssessmentHistory(userId, filters = {}) {
        const queryParams = new URLSearchParams({
            user_id: userId,
            ...filters
        });

        const response = await axios.get(`${this.baseURL}/identity/history?${queryParams}`, {
            headers: {
                'Authorization': `Bearer ${this.apiKey}`
            },
            timeout: this.timeout
        });
        
        return response.data;
    }
}
```

**NexShop Service Integration Points with SDK Flow**

1. **Authentication Flow with IDROCK SDK Integration**
```javascript
// authService.js
async function authenticateUser(username, password, req) {
    // Get user IP and other metadata
    const userData = {
        userId: username,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        actionType: 'login'
    };

    // Call IDROCK via Node.js SDK for risk assessment
    const riskAssessment = await idrockClient.verifyIdentity(userData);
    
    switch (riskAssessment.risk_level) {
        case 'DENY':
            throw new AuthenticationError('Login blocked due to security concerns');
        case 'REVIEW':
            // Require additional authentication steps
            return await handleEnhancedAuth(username, password, riskAssessment);
        case 'ALLOW':
            // Proceed with normal authentication
            return await validateUserCredentials(username, password);
    }
}
```

2. **Checkout Protection Integration with SDK**
```javascript
// orderService.js
async function processOrder(orderData, req) {
    const userData = {
        userId: orderData.userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        actionType: 'checkout',
        amount: orderData.totalAmount
    };

    // Get risk assessment from IDROCK via Node.js SDK  
    const riskAssessment = await idrockClient.verifyIdentity(userData);
    
    // Log security assessment locally
    await SecurityLog.create({
        userId: orderData.userId,
        actionType: 'checkout',
        riskLevel: riskAssessment.risk_level,
        confidenceScore: riskAssessment.confidence_score,
        ipAddress: userData.ipAddress,
        timestamp: new Date()
    });

    switch (riskAssessment.risk_level) {
        case 'ALLOW':
            return await processNormalCheckout(orderData);
        case 'REVIEW':
            return await processReviewRequiredCheckout(orderData, riskAssessment);
        case 'DENY':
            throw new CheckoutError('Transaction blocked for security reasons');
    }
}
```

**Service Communication Configuration**
```javascript
// config/idrock.js
module.exports = {
    idrockApi: {
        baseUrl: process.env.IDROCK_API_URL || 'http://localhost:8000',
        apiKey: process.env.IDROCK_API_KEY,
        timeout: parseInt(process.env.IDROCK_TIMEOUT) || 5000,
        retryAttempts: 3,
        retryDelay: 1000
    }
};
```

### NexShop E-commerce Integration (MVP - Two Independent Services)

#### Integration Architecture (MVP Scope)

**MVP Phase: IP Reputation Based Security**
- NexShop Node.js/Express backend with React frontend
- Separate SQLite database for e-commerce data
- HTTP API calls to IDROCK FastAPI service for security assessments
- JavaScript SDK integration for client-side data collection
- Login and checkout protection using IP reputation only
- Simplified risk assessment responses (ALLOW/REVIEW/DENY)

**Service Communication**:
- NexShop backend calls IDROCK API over HTTP using Axios
- No direct database sharing between services
- Independent manual deployment
- Clear JSON-based API contract between services
- Error handling with fallback to allow transactions if IDROCK unavailable

**Future Phases** (Post-MVP):
- Enhanced protection with multiple risk factors
- Behavioral analysis integration
- Advanced device fingerprinting
- Multi-factor authentication triggers

#### NexShop Node.js Backend Integration

**Express.js Middleware Integration**
```javascript
// middleware/security.js - IDROCK security middleware
const IDRockAPIClient = require('../services/idrockClient');

class SecurityMiddleware {
    constructor(idrockClient) {
        this.idrockClient = idrockClient;
    }

    // Middleware for login protection
    async protectLogin(req, res, next) {
        try {
            const userData = {
                userId: req.body.username,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                actionType: 'login'
            };

            const riskAssessment = await this.idrockClient.verifyIdentity(userData);
            
            // Add risk assessment to request for downstream processing
            req.riskAssessment = riskAssessment;
            
            if (riskAssessment.risk_level === 'DENY') {
                return res.status(403).json({
                    error: 'Login blocked due to security concerns',
                    riskLevel: riskAssessment.risk_level,
                    requestId: riskAssessment.metadata.request_id
                });
            }
            
            next();
        } catch (error) {
            // Fallback: allow login if IDROCK is unavailable
            console.error('IDROCK API unavailable, allowing login:', error.message);
            next();
        }
    }

    // Middleware for checkout protection
    async protectCheckout(req, res, next) {
        try {
            const userData = {
                userId: req.user.id, // From authentication middleware
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                actionType: 'checkout',
                amount: req.body.totalAmount
            };

            const riskAssessment = await this.idrockClient.verifyIdentity(userData);
            req.riskAssessment = riskAssessment;
            
            switch (riskAssessment.risk_level) {
                case 'DENY':
                    return res.status(403).json({
                        error: 'Transaction blocked for security reasons',
                        riskLevel: riskAssessment.risk_level,
                        requestId: riskAssessment.metadata.request_id
                    });
                case 'REVIEW':
                    // Flag for additional verification
                    req.requiresReview = true;
                    break;
            }
            
            next();
        } catch (error) {
            // Fallback: allow checkout if IDROCK is unavailable
            console.error('IDROCK API unavailable, allowing checkout:', error.message);
            next();
        }
    }
}

module.exports = SecurityMiddleware;
```

**Express.js Route Integration**
```javascript
// routes/auth.js - Authentication routes with IDROCK
const express = require('express');
const SecurityMiddleware = require('../middleware/security');
const AuthService = require('../services/authService');

const router = express.Router();
const securityMiddleware = new SecurityMiddleware(idrockClient);

// Login with IDROCK protection
router.post('/login', 
    securityMiddleware.protectLogin,
    async (req, res) => {
        try {
            const { username, password } = req.body;
            const riskAssessment = req.riskAssessment;

            // Handle different risk levels
            if (riskAssessment && riskAssessment.risk_level === 'REVIEW') {
                // Require additional authentication
                return res.json({
                    status: 'additional_verification_required',
                    message: 'Please complete additional security verification',
                    verificationMethods: ['sms', 'email'],
                    sessionToken: await AuthService.createSecureSession(username)
                });
            }

            // Proceed with normal login
            const authResult = await AuthService.authenticate(username, password);
            
            // Log security assessment
            await SecurityLog.create({
                userId: username,
                actionType: 'login',
                riskLevel: riskAssessment?.risk_level || 'UNKNOWN',
                confidenceScore: riskAssessment?.confidence_score || 0,
                ipAddress: req.ip
            });

            res.json(authResult);
        } catch (error) {
            res.status(401).json({ error: error.message });
        }
    }
);

module.exports = router;
```

**React Frontend Integration**
```javascript
// hooks/useIDRock.js - React hook for IDROCK SDK
import { useState, useCallback } from 'react';
import IDRockSDK from '../utils/idrockSDK';

export const useIDRock = () => {
    const [isAssessing, setIsAssessing] = useState(false);
    
    const assessRisk = useCallback(async (actionData) => {
        setIsAssessing(true);
        try {
            const sdk = new IDRockSDK();
            const assessment = await sdk.assessRisk(actionData);
            return assessment;
        } catch (error) {
            console.error('Risk assessment failed:', error);
            return null; // Graceful degradation
        } finally {
            setIsAssessing(false);
        }
    }, []);

    return { assessRisk, isAssessing };
};

// components/CheckoutForm.js - React component with IDROCK
import React, { useState } from 'react';
import { useIDRock } from '../hooks/useIDRock';

const CheckoutForm = ({ orderData }) => {
    const { assessRisk, isAssessing } = useIDRock();
    const [requiresReview, setRequiresReview] = useState(false);

    const handleCheckout = async () => {
        try {
            // Backend handles the risk assessment via middleware
            const response = await fetch('/api/orders/checkout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(orderData)
            });

            const result = await response.json();
            
            if (result.requiresReview) {
                setRequiresReview(true);
                // Show additional verification form
            } else {
                // Proceed with normal checkout flow
                handleSuccessfulCheckout(result);
            }
        } catch (error) {
            console.error('Checkout failed:', error);
        }
    };

    return (
        <div className="checkout-form">
            {/* Checkout form components */}
            {requiresReview && (
                <AdditionalVerificationForm onVerified={handleCheckout} />
            )}
            <button 
                onClick={handleCheckout} 
                disabled={isAssessing}
                className="checkout-button"
            >
                {isAssessing ? 'Processing...' : 'Complete Order'}
            </button>
        </div>
    );
};
```

### SDK Design

#### IDROCK JavaScript SDK Architecture (Frontend)

The IDROCK JavaScript SDK is designed specifically for NexShop frontend integration to collect and generate necessary information for the backend.

```javascript
class IDRockSDK {
    constructor(config) {
        this.config = {
            apiEndpoint: config.apiEndpoint || 'http://localhost:3000/api/idrock',
            timeout: config.timeout || 5000,
            retryAttempts: config.retryAttempts || 3,
            debug: config.debug || false
        };
        this.fingerprint = new FingerprintCollector();
        this.sessionData = new SessionDataCollector();
    }
    
    /**
     * Collect device information and session data for risk assessment
     * This data is sent to NexShop backend, NOT directly to IDROCK API
     */
    async collectRiskData(actionType, additionalData = {}) {
        try {
            const deviceFingerprint = await this.fingerprint.collect();
            const sessionInfo = this.sessionData.collect();
            
            const riskData = {
                action_type: actionType, // 'login' | 'checkout' | 'sensitive_action'
                device_fingerprint: deviceFingerprint,
                session_data: sessionInfo,
                user_agent: navigator.userAgent,
                timestamp: new Date().toISOString(),
                additional_data: additionalData
            };
            
            if (this.config.debug) {
                console.log('IDROCK SDK: Risk data collected', riskData);
            }
            
            return riskData;
        } catch (error) {
            console.error('IDROCK SDK: Failed to collect risk data', error);
            return this._getFallbackData(actionType, additionalData);
        }
    }
    
    /**
     * Send collected data to NexShop backend for processing
     * NexShop backend will use Node.js SDK to communicate with IDROCK API
     */
    async sendToBackend(riskData, endpoint = '/api/security/assess') {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(riskData),
                signal: AbortSignal.timeout(this.config.timeout)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('IDROCK SDK: Failed to send data to backend', error);
            throw error;
        }
    }
    
    /**
     * Convenience method for login assessment
     */
    async assessLogin(username, additionalData = {}) {
        const riskData = await this.collectRiskData('login', { 
            username, 
            ...additionalData 
        });
        return this.sendToBackend(riskData, '/api/auth/login');
    }
    
    /**
     * Convenience method for checkout assessment
     */
    async assessCheckout(orderData) {
        const riskData = await this.collectRiskData('checkout', {
            order_amount: orderData.totalAmount,
            payment_method: orderData.paymentMethod,
            shipping_address: orderData.shippingAddress
        });
        return this.sendToBackend(riskData, '/api/orders/checkout');
    }
    
    collectSessionData() {
        return {
            timestamp: new Date().toISOString(),
            user_agent: navigator.userAgent,
            browser_info: {
                device_memory: navigator.deviceMemory,
                hardware_concurrency: navigator.hardwareConcurrency,
                screen_resolution: `${screen.width}x${screen.height}`,
                color_depth: screen.colorDepth,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
            },
            page_info: {
                url: window.location.href,
                referrer: document.referrer,
                title: document.title
            }
        };
    }
    
    _getFallbackData(actionType, additionalData) {
        return {
            action_type: actionType,
            device_fingerprint: 'fallback_' + Date.now(),
            session_data: {
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent || 'unknown',
                fallback: true
            },
            user_agent: navigator.userAgent || 'unknown',
            timestamp: new Date().toISOString(),
            additional_data: additionalData
        };
    }
}

// Fingerprint Collection Utility
class FingerprintCollector {
    async collect() {
        try {
            const components = await Promise.allSettled([
                this.getCanvasFingerprint(),
                this.getWebGLFingerprint(),
                this.getAudioFingerprint(),
                this.getBrowserFeatures()
            ]);
            
            const fingerprint = components
                .filter(result => result.status === 'fulfilled')
                .map(result => result.value)
                .join('|');
                
            return this.hashFingerprint(fingerprint);
        } catch (error) {
            console.error('Fingerprint collection failed:', error);
            return 'fallback_' + Date.now();
        }
    }
    
    async getCanvasFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('IDROCK fingerprint', 2, 2);
        return canvas.toDataURL();
    }
    
    // Additional fingerprinting methods...
    hashFingerprint(data) {
        // Simple hash function for fingerprint
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(36);
    }
}
```

#### IDROCK Node.js SDK Architecture (Backend)

The IDROCK Node.js SDK is designed for NexShop backend to communicate directly with the IDROCK FastAPI service.

```javascript
class IDRockNodeSDK {
    constructor(config) {
        this.config = {
            apiBaseUrl: config.apiBaseUrl || 'http://localhost:8000',
            apiKey: config.apiKey,
            timeout: config.timeout || 5000,
            retryAttempts: config.retryAttempts || 3,
            retryDelay: config.retryDelay || 1000
        };
        this.httpClient = axios.create({
            baseURL: this.config.apiBaseUrl,
            timeout: this.config.timeout,
            headers: {
                'Authorization': `Bearer ${this.config.apiKey}`,
                'Content-Type': 'application/json',
                'User-Agent': 'IDROCK-NodeSDK/1.0.0'
            }
        });
        
        this.setupInterceptors();
    }
    
    /**
     * Main method to verify identity using IDROCK API
     * This is called by NexShop backend after receiving data from JavaScript SDK
     */
    async verifyIdentity(userData) {
        const payload = {
            user_id: userData.userId,
            ip_address: userData.ipAddress,
            user_agent: userData.userAgent,
            session_data: {
                timestamp: userData.timestamp || new Date().toISOString(),
                device_fingerprint: userData.deviceFingerprint,
                ...userData.sessionData
            },
            context: {
                action_type: userData.actionType, // 'login' | 'checkout' | 'sensitive_action'
                amount: userData.amount, // for checkout operations
                additional_context: userData.additionalContext
            }
        };

        try {
            const response = await this.httpClient.post('/identity/verify', payload);
            return response.data;
        } catch (error) {
            throw new IDRockAPIError(error);
        }
    }
    
    /**
     * Get assessment history from IDROCK API
     */
    async getAssessmentHistory(userId, filters = {}) {
        const params = {
            user_id: userId,
            ...filters
        };

        try {
            const response = await this.httpClient.get('/identity/history', { params });
            return response.data;
        } catch (error) {
            throw new IDRockAPIError(error);
        }
    }
    
    /**
     * Health check for IDROCK service
     */
    async healthCheck() {
        try {
            const response = await this.httpClient.get('/health');
            return response.data;
        } catch (error) {
            throw new IDRockAPIError(error);
        }
    }
    
    setupInterceptors() {
        // Request interceptor for logging
        this.httpClient.interceptors.request.use(
            config => {
                console.log(`IDROCK SDK Request: ${config.method.toUpperCase()} ${config.url}`);
                return config;
            },
            error => Promise.reject(error)
        );
        
        // Response interceptor for retry logic
        this.httpClient.interceptors.response.use(
            response => response,
            async error => {
                const config = error.config;
                if (!config._retry && config._retryCount < this.config.retryAttempts) {
                    config._retryCount = (config._retryCount || 0) + 1;
                    config._retry = true;
                    
                    await this.delay(this.config.retryDelay * config._retryCount);
                    return this.httpClient(config);
                }
                return Promise.reject(error);
            }
        );
    }
    
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Custom error class for IDROCK API errors
class IDRockAPIError extends Error {
    constructor(originalError) {
        super(originalError.message);
        this.name = 'IDRockAPIError';
        this.status = originalError.response?.status;
        this.statusText = originalError.response?.statusText;
        this.data = originalError.response?.data;
        this.originalError = originalError;
    }
}

module.exports = { IDRockNodeSDK, IDRockAPIError };
```

#### SDK Integration Features

**JavaScript SDK (Frontend) Capabilities**
- Device fingerprinting and session data collection
- Automatic risk data generation for backend processing
- Support for login, checkout, and sensitive action workflows
- Error handling with graceful fallbacks
- Configurable endpoints and timeouts
- Debug mode for development

**Node.js SDK (Backend) Capabilities**
- Direct communication with IDROCK FastAPI service
- Automatic retry logic with exponential backoff
- Comprehensive error handling and logging
- Support for all IDROCK API endpoints
- Request/response interceptors for monitoring
- Authentication and authorization management

**Integration Methods**
- **JavaScript SDK**: NPM package, CDN script, React/Vue/Angular components
- **Node.js SDK**: NPM package for Express.js/Node.js backends
- Vanilla JavaScript support for simple integrations
- TypeScript definitions for both SDKs

**Configuration Options**
- API endpoint customization for different environments
- Timeout and retry configuration
- Authentication key management
- Debug and logging level settings
- Custom headers and middleware support

### SDK Documentation and Usage Examples

#### IDROCK JavaScript SDK Installation and Setup

**NPM Installation**
```bash
npm install @idrock/js-sdk
```

**CDN Usage**
```html
<script src="https://cdn.idrock.com/sdk/js/v1.0.0/idrock-sdk.min.js"></script>
```

**Basic Initialization**
```javascript
import IDRockSDK from '@idrock/js-sdk';

// Initialize SDK for NexShop integration
const idrockSDK = new IDRockSDK({
    apiEndpoint: 'https://nexshop.com/api/idrock',  // NexShop backend endpoint
    timeout: 5000,
    retryAttempts: 3,
    debug: process.env.NODE_ENV === 'development'
});
```

#### JavaScript SDK Usage Examples

**1. Login Risk Assessment**
```javascript
// Login form component
const LoginForm = () => {
    const handleLogin = async (username, password) => {
        try {
            // Collect risk data and send to NexShop backend
            const result = await idrockSDK.assessLogin(username, {
                loginAttemptCount: getLoginAttemptCount(username),
                lastLoginTime: getLastLoginTime(username)
            });
            
            // Handle response from NexShop backend
            switch (result.riskLevel) {
                case 'ALLOW':
                    // Proceed with normal login
                    await authenticateUser(username, password);
                    break;
                case 'REVIEW':
                    // Show additional verification
                    showTwoFactorAuthentication();
                    break;
                case 'DENY':
                    // Block login attempt
                    showSecurityAlert('Login blocked for security reasons');
                    break;
            }
        } catch (error) {
            console.error('Login risk assessment failed:', error);
            // Graceful fallback - proceed with normal login
            await authenticateUser(username, password);
        }
    };
};
```

**2. Checkout Risk Assessment**
```javascript
// Checkout form component
const CheckoutForm = ({ orderData }) => {
    const processCheckout = async () => {
        try {
            // Assess checkout risk
            const result = await idrockSDK.assessCheckout({
                totalAmount: orderData.total,
                paymentMethod: orderData.paymentMethod,
                shippingAddress: orderData.shippingAddress,
                itemCount: orderData.items.length
            });
            
            // Handle risk assessment result
            if (result.riskLevel === 'ALLOW') {
                await processPayment(orderData);
            } else if (result.riskLevel === 'REVIEW') {
                await showAdditionalVerification();
            } else {
                showCheckoutBlocked();
            }
        } catch (error) {
            console.error('Checkout assessment failed:', error);
            // Fallback to normal checkout
            await processPayment(orderData);
        }
    };
};
```

**3. Custom Risk Data Collection**
```javascript
// Advanced usage with custom data
const collectCustomRiskData = async () => {
    const riskData = await idrockSDK.collectRiskData('sensitive_action', {
        actionType: 'password_change',
        accountAge: getUserAccountAge(),
        previousSensitiveActions: getPreviousActions(),
        customFingerprint: await getCustomFingerprint()
    });
    
    // Send to custom NexShop endpoint
    return await idrockSDK.sendToBackend(riskData, '/api/security/custom-assess');
};
```

#### IDROCK Node.js SDK Installation and Setup

**NPM Installation**
```bash
npm install @idrock/node-sdk
```

**Basic Configuration**
```javascript
const { IDRockNodeSDK } = require('@idrock/node-sdk');

// Configure SDK for NexShop backend
const idrockClient = new IDRockNodeSDK({
    apiBaseUrl: process.env.IDROCK_API_URL || 'https://api.idrock.com',
    apiKey: process.env.IDROCK_API_KEY,
    timeout: 5000,
    retryAttempts: 3,
    retryDelay: 1000
});
```

#### Node.js SDK Usage Examples

**1. Express.js Middleware Integration**
```javascript
// Security middleware using IDROCK Node.js SDK
const createIDRockMiddleware = (idrockClient) => {
    return async (req, res, next) => {
        try {
            const userData = {
                userId: req.user?.id || req.body.username,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                actionType: req.route.path.includes('login') ? 'login' : 'checkout',
                deviceFingerprint: req.body.deviceFingerprint,
                sessionData: req.body.sessionData,
                additionalContext: req.body.additionalData
            };
            
            // Call IDROCK API through Node.js SDK
            const assessment = await idrockClient.verifyIdentity(userData);
            
            // Add assessment to request
            req.idrockAssessment = assessment;
            
            // Handle risk levels
            switch (assessment.risk_level) {
                case 'DENY':
                    return res.status(403).json({
                        error: 'Action blocked for security reasons',
                        requestId: assessment.metadata.request_id
                    });
                case 'REVIEW':
                    req.requiresAdditionalVerification = true;
                    break;
            }
            
            next();
        } catch (error) {
            console.error('IDROCK assessment failed:', error);
            // Graceful fallback - allow action
            next();
        }
    };
};

// Apply middleware to routes
app.use('/api/auth/login', createIDRockMiddleware(idrockClient));
app.use('/api/orders/checkout', createIDRockMiddleware(idrockClient));
```

**2. Service-Level Integration**
```javascript
// Authentication service with IDROCK integration
class AuthService {
    constructor(idrockClient) {
        this.idrockClient = idrockClient;
    }
    
    async authenticateWithRiskAssessment(userData) {
        try {
            // Get risk assessment from IDROCK API
            const assessment = await this.idrockClient.verifyIdentity({
                userId: userData.username,
                ipAddress: userData.ipAddress,
                userAgent: userData.userAgent,
                actionType: 'login',
                deviceFingerprint: userData.deviceFingerprint,
                sessionData: userData.sessionData
            });
            
            // Log assessment locally
            await this.logSecurityAssessment(userData.username, assessment);
            
            // Apply risk-based logic
            switch (assessment.risk_level) {
                case 'ALLOW':
                    return await this.standardLogin(userData);
                case 'REVIEW':
                    return await this.enhancedLogin(userData, assessment);
                case 'DENY':
                    throw new SecurityError('Login blocked');
            }
        } catch (error) {
            if (error instanceof SecurityError) {
                throw error;
            }
            // Fallback for IDROCK API issues
            console.warn('IDROCK unavailable, proceeding with standard login');
            return await this.standardLogin(userData);
        }
    }
}
```

**3. History and Analytics Integration**
```javascript
// Analytics service using IDROCK history data
class SecurityAnalytics {
    constructor(idrockClient) {
        this.idrockClient = idrockClient;
    }
    
    async getUserSecurityReport(userId, days = 30) {
        try {
            const endDate = new Date();
            const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
            
            const history = await this.idrockClient.getAssessmentHistory(userId, {
                start_date: startDate.toISOString(),
                end_date: endDate.toISOString(),
                limit: 1000
            });
            
            return this.analyzeSecurityPatterns(history.data);
        } catch (error) {
            console.error('Failed to fetch security history:', error);
            return this.getDefaultSecurityReport();
        }
    }
    
    analyzeSecurityPatterns(assessments) {
        const totalAssessments = assessments.length;
        const riskDistribution = this.calculateRiskDistribution(assessments);
        const averageConfidence = this.calculateAverageConfidence(assessments);
        const suspiciousPatterns = this.detectSuspiciousPatterns(assessments);
        
        return {
            totalAssessments,
            riskDistribution,
            averageConfidence,
            suspiciousPatterns,
            recommendedActions: this.getRecommendedActions(riskDistribution)
        };
    }
}
```

#### SDK Integration Best Practices

**1. Error Handling and Fallbacks**
```javascript
// Robust error handling with graceful degradation
const performSecureAction = async (actionData) => {
    const MAX_RETRIES = 3;
    let attempt = 0;
    
    while (attempt < MAX_RETRIES) {
        try {
            const assessment = await idrockSDK.assessRisk(actionData);
            return await handleAssessment(assessment);
        } catch (error) {
            attempt++;
            console.warn(`IDROCK attempt ${attempt} failed:`, error.message);
            
            if (attempt >= MAX_RETRIES) {
                console.warn('IDROCK unavailable, proceeding without assessment');
                return await handleWithoutAssessment(actionData);
            }
            
            // Exponential backoff
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
        }
    }
};
```

**2. Performance Optimization**
```javascript
// SDK configuration for optimal performance
const optimizedSDK = new IDRockSDK({
    // Reduce timeout for faster fallbacks
    timeout: 3000,
    // Limit retry attempts
    retryAttempts: 2,
    // Cache fingerprints to avoid recalculation
    cacheDuration: 300000, // 5 minutes
    // Batch risk assessments when possible
    enableBatching: true,
    batchSize: 10,
    batchTimeout: 1000
});
```

**3. Development and Testing**
```javascript
// SDK testing utilities
const createMockIDRockSDK = (mockResponses) => {
    return {
        assessLogin: jest.fn().mockImplementation((username) => 
            Promise.resolve(mockResponses.login[username] || mockResponses.default)
        ),
        assessCheckout: jest.fn().mockImplementation(() => 
            Promise.resolve(mockResponses.checkout || mockResponses.default)
        ),
        collectRiskData: jest.fn().mockImplementation(() => 
            Promise.resolve(mockResponses.riskData || {})
        )
    };
};

// Unit test example
describe('LoginService with IDROCK', () => {
    it('should handle high-risk login attempts', async () => {
        const mockSDK = createMockIDRockSDK({
            default: { riskLevel: 'DENY', confidenceScore: 15 }
        });
        
        const loginService = new LoginService(mockSDK);
        
        await expect(loginService.login('suspicious_user', 'password'))
            .rejects.toThrow('Login blocked');
    });
});
```

### Security Considerations

#### Data Protection
- End-to-end encryption for sensitive data
- PII data anonymization
- GDPR compliance measures
- Data retention policies
- Secure API key management

#### Authentication and Authorization
- API key authentication
- JWT token validation
- Role-based access control
- Rate limiting
- IP whitelisting options

#### Infrastructure Security
- HTTPS/TLS encryption
- WAF protection
- DDoS mitigation
- Security headers implementation
- Container security scanning

#### Privacy Compliance
- GDPR Article 6 lawful basis
- Privacy by design principles
- Data minimization practices
- User consent management
- Right to be forgotten implementation

### Implementation Phases (Two Independent Services with SDK Priority)

#### Phase 1: IDROCK Security Service Foundation (Weeks 1-3)
**Sprint 1: IDROCK API Core & Documentation**
- FastAPI project setup with automatic OpenAPI generation
- SQLite database schema design and setup
- Core API endpoints implementation (/identity/verify, /health)
- Swagger/OpenAPI documentation configuration
- Basic authentication and security setup
- Docker container configuration

**Sprint 2: Risk Engine & SDK Preparation**
- ProxyCheck.io API integration for IP reputation analysis
- Simplified risk scoring algorithm implementation (IP-only)
- API schema validation for SDK integration
- Unit tests for core IDROCK functionality
- API error handling and fallback mechanisms
- Manual testing with Postman/Insomnia

#### Phase 2: SDK Development & E-commerce Service (Weeks 4-7)
**Sprint 3: IDROCK SDK Development (Priority)**
- **IDROCK JavaScript SDK (Frontend)** - Device fingerprinting and data collection
- **IDROCK Node.js SDK (Backend)** - Direct API communication with IDROCK service
- SDK error handling, retry logic, and fallback mechanisms
- NPM package setup and distribution preparation
- SDK unit testing and documentation
- SDK integration examples and usage guides

**Sprint 4: NexShop Backend with SDK Integration**
- Node.js/Express.js project setup
- SQLite database schema for e-commerce (Sequelize)
- IDROCK Node.js SDK integration in NexShop backend
- Security middleware using IDROCK Node.js SDK
- User, Product, Order models implementation
- Docker container configuration

**Sprint 5: NexShop Frontend with SDK Integration**
- React frontend setup and components
- IDROCK JavaScript SDK integration in NexShop frontend
- Custom React hooks for IDROCK SDK usage
- Login and checkout forms with SDK data collection
- Error handling and user experience optimization
- Frontend-backend integration testing

#### Phase 3: End-to-End Integration & Testing (Weeks 8-10)
**Sprint 6: Complete SDK Integration Flow**
- End-to-end testing: Frontend SDK → Backend SDK → IDROCK API
- Service-to-service communication validation
- Error handling across the complete integration chain
- Performance optimization for SDK data flow
- User experience testing and refinement

**Sprint 7: Advanced Features & Documentation**
- /identity/history endpoint with filtering and pagination
- SDK advanced configuration options
- Comprehensive API and SDK documentation
- Integration testing framework for both services
- SDK versioning and backward compatibility

#### Phase 4: Deployment & SDK Distribution (Weeks 11-12)
**Sprint 8: SDK Publishing & Service Deployment**
- NPM package publishing for both SDKs
- Docker deployment procedures for both services
- SDK documentation website and examples
- Manual deployment testing procedures
- CDN setup for JavaScript SDK distribution

**Sprint 9: Launch & SDK Support**
- Service launch with manual oversight
- SDK support documentation and troubleshooting
- Performance monitoring for services and SDK usage
- Bug fixes and SDK improvements
- User feedback integration for SDK usability

### Testing Strategy

#### API Unit Testing
- FastAPI endpoint testing with pytest and FastAPI TestClient
- Individual service function testing (risk engine, external integrations)
- Database model and operations testing
- Pydantic schema validation testing
- Error handling and edge case testing

#### API Integration Testing
- End-to-end API workflow testing
- Database integration testing with real PostgreSQL
- External service integration testing (ProxyCheck.io API)
- SQLite database integration testing
- Authentication and authorization flow testing

#### SDK Testing
- JavaScript SDK functionality testing (Jest)
- Cross-browser compatibility testing
- SDK integration testing with mock API responses
- Error handling and retry logic testing
- Performance testing of SDK fingerprinting capabilities

#### Performance Testing
- API load testing using pytest-benchmark and locust
- Database query performance optimization testing
- Response time benchmarking for all endpoints
- Concurrent request handling testing
- Memory usage and resource optimization testing

#### Security Testing
- API security testing with OWASP ZAP
- Input validation and SQL injection testing
- Authentication bypass and authorization testing
- Rate limiting effectiveness testing
- SSL/TLS configuration testing

#### Test Coverage Goals
- Backend API: 90%+ test coverage
- Services and utilities: 95%+ test coverage
- SDK: 90%+ test coverage
- Integration tests: All critical API paths
- Performance benchmarks: Sub-200ms API response time

### Deployment Considerations

#### Infrastructure Requirements

**Development Environment**
- Docker containers for local development
- PostgreSQL 14+ database
- SQLite for data storage (both services)
- Python 3.9+ runtime
- Node.js 16+ for SDK development and testing only

**Staging Environment**
- Docker container deployment for API services
- Managed PostgreSQL (AWS RDS/Google Cloud SQL)
- SQLite file-based storage
- Load balancer configuration for API endpoints
- SSL certificate management and API security

**Production Environment**
- Manual Docker deployment for API services
- High-availability database setup with read replicas
- SQLite database optimization and indexing
- CDN integration for SDK distribution and API docs
- Comprehensive monitoring and alerting systems

#### Manual Deployment Process

**Deployment Steps**:
1. **Local Testing**
   - Run unit tests for both services
   - Integration testing between services
   - Manual API testing with Postman
   - Database migration testing

2. **Service Deployment**
   - Build Docker containers for each service
   - Deploy IDROCK FastAPI service
   - Deploy NexShop Node.js service
   - Verify service-to-service communication

3. **Configuration and Validation**
   - Configure environment variables
   - Set up SQLite databases
   - Test API endpoints manually
   - Validate security configurations

#### Monitoring and Observability

**API Performance Monitoring**
- API response times and error rates for all endpoints
- Request throughput and rate limiting effectiveness
- Database query performance and connection pooling
- SQLite query performance and optimization
- Business metrics (fraud detection rates and accuracy)

**Infrastructure Monitoring**
- Docker container resource utilization
- Database server performance and connection health
- SQLite database file size and performance
- Network latency and API gateway performance
- Container resource usage and scaling metrics

**Security and Compliance Monitoring**
- Failed authentication and authorization attempts
- Unusual API access patterns and rate limiting triggers
- Security vulnerability scanning and alerting
- Compliance audit logs and data retention policies
- External API integration health (ProxyCheck.io)

#### Scalability Planning

**Horizontal Scaling**
- Manual scaling considerations for Docker containers
- PostgreSQL read replicas for history queries
- SQLite database optimization and indexing
- CDN geographic distribution for SDK and documentation
- Load balancer configuration with health checks

**Performance Optimization**
- Database query optimization with proper indexing
- Direct database access without caching layer
- CDN implementation for static assets (SDK, docs)
- Connection pooling optimization
- Async processing for non-critical operations

### Success Metrics and KPIs

#### Business Metrics
- Fraud detection accuracy: >95%
- False positive rate: <5%
- Average response time: <200ms
- Customer satisfaction: >90%
- ROI improvement: >300%

#### Technical Metrics
- API uptime: 99.9%
- System availability: 99.95%
- Database performance: <50ms queries
- API response time: <200ms for all endpoints
- SDK integration time: <30 minutes

#### Security Metrics
- Zero security breaches
- Compliance audit success: 100%
- Vulnerability resolution: <24 hours
- Security training completion: 100%
- Incident response time: <15 minutes

### Risk Management

#### Technical Risks
- Third-party API dependencies (ProxyCheck.io)
- Scaling challenges under high load
- Browser compatibility issues
- Performance degradation
- Data privacy compliance

#### Business Risks
- Customer adoption resistance
- Integration complexity
- Competitive market pressure
- Regulatory changes
- Budget constraints

#### Mitigation Strategies
- Multiple vendor redundancy
- Comprehensive testing strategy
- Gradual rollout approach
- Continuous monitoring
- Regular security audits

### Conclusion

This comprehensive project plan provides a roadmap for developing the IDROCK IP reputation security tool as a dual-SDK integrated solution. The development framework ensures systematic development with quality gates at each phase. The architecture focuses on clean service separation through SDK integration, supporting scalability, maintainability, and effective fraud detection capabilities.

The dual-SDK approach provides optimal service integration while maintaining independence:
- **Clean Service Separation**: IDROCK and NexShop maintain independent databases and deployment cycles
- **Seamless Integration**: JavaScript SDK for frontend data collection, Node.js SDK for backend API communication
- **Proper Data Flow**: Frontend SDK → NexShop Backend → Node.js SDK → IDROCK FastAPI → ProxyCheck.io
- **Comprehensive Documentation**: SDK usage examples, API documentation, and integration guides
- **Production Ready**: Built-in monitoring, security, and scalability features with graceful fallbacks

The SDK-priority implementation approach ensures:
- **Frontend JavaScript SDK**: Device fingerprinting and risk data collection for NexShop frontend
- **Backend Node.js SDK**: Direct communication with IDROCK FastAPI service from NexShop backend
- **Service Independence**: Each service maintains its own SQLite database and deployment lifecycle
- **Clear Integration Boundaries**: Well-defined API contracts and SDK interfaces

The phased implementation prioritizes SDK development in Phase 2, allowing for iterative development and comprehensive testing. The integration with NexShop demonstrates practical application while the SDK design enables broad adoption across multiple e-commerce platforms.

This architecture reduces integration complexity while maintaining service independence, making it ideal for teams that need secure fraud detection capabilities without tightly coupling their systems to external services. The SDK-mediated communication pattern ensures proper separation of concerns while delivering seamless user experiences.

---

**Document Version**: 1.0  
**Last Updated**: 2025-09-07  
**Framework Compliance**: Secure Development Best Practices  
**Review Status**: Ready for Implementation
