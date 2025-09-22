# IDROCK - Security Tool

**Sistema de Análise de Reputação de Acesso para Determinação de Risco de Fraude**

## 🚀 Overview

IDROCK is a comprehensive IP reputation security tool designed to provide real-time fraud risk assessment for e-commerce platforms. The system consists of two independent services integrated via SDKs:

- **IDROCK Security Service** (FastAPI) - Core risk assessment engine
- **NexShop E-commerce Service** (Node.js/Express) - Demo e-commerce platform

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           IDROCK SECURITY TOOL                        │
│                         (Independent Service)                          │
└─────────────────────────────────────────────────────────────────────────┘
                    ┌──────────────────┐    ┌─────────────────┐
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
│   React         │◄──►│   Node.js        │◄──►│   SQLite         │
│   Frontend      │    │   Express.js     │    │   Database       │
│   + JS SDK      │    │   Backend        │    │   (E-commerce)   │
│                 │    │   + Node.js SDK  │    │                  │
└─────────────────┘    └──────────────────┘    └──────────────────┘
```

## ✨ Features

### Advanced Security Implementation (Complete)
- **Real-time IP reputation analysis** using ProxyCheck.io
- **Device Trust Management System** with unique constraints to prevent cloning
- **Impossible Travel Detection** with geodesic calculations and speed thresholds
- **Hardware Validation System** detecting real computers vs automation tools
- **Browser Automation Detection** with comprehensive pattern matching
- **Risk scoring** (0-100) with adaptive thresholds and weighted factors
- **Risk levels**: ALLOW (70-100), REVIEW (30-69), DENY (0-29)
- **Dual SDK integration** for seamless service communication
- **Comprehensive logging** and audit trails with device access history
- **Docker containerization** for easy deployment
- **Interactive API documentation** (Swagger/OpenAPI)

### Advanced Risk Assessment Process
1. Frontend JavaScript SDK collects comprehensive device fingerprinting data (Canvas, WebGL, Audio)
2. Device registration and trust management with unique constraint validation
3. Hardware validation (CPU cores, RAM) and browser automation detection
4. Data flows to NexShop backend via secure endpoints
5. NexShop Node.js SDK communicates with IDROCK API
6. IDROCK analyzes multiple risk factors:
   - IP reputation via ProxyCheck.io
   - Impossible travel detection using geodesic calculations
   - Device trust status and access history
   - Hardware authenticity validation
   - Browser automation pattern matching
7. Weighted risk score calculated with multi-factor analysis
8. Recommendations generated with detailed risk breakdown
9. Response flows back through the SDK chain with comprehensive analysis

## 🛠️ Technology Stack

### IDROCK Security Service
- **FastAPI** (Python 3.9+) - Main API framework
- **SQLAlchemy** + **SQLite** - Database and ORM with advanced device models
- **Alembic** - Database migrations and schema management
- **Pydantic** - Data validation and API schemas
- **httpx** - Async HTTP client for external APIs
- **geopy** - Geodesic distance calculations for travel detection
- **ProxyCheck.io** - IP reputation analysis

### NexShop E-commerce Service  
- **Node.js** (v18+) + **Express.js** - Backend framework
- **Sequelize** + **SQLite** - Database ORM
- **JWT** - Authentication and authorization
- **bcryptjs** - Password hashing
- **axios** - HTTP client for IDROCK API

### SDKs
- **JavaScript SDK** - Advanced frontend data collection with Canvas, WebGL, Audio fingerprinting
- **Node.js SDK** - Backend API communication with retry logic and device management

## 🚦 Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for local development)
- Python 3.9+ (for local development)

### 1. Environment Setup
```bash
# Clone the repository
git clone <repository-url>
cd idrock-new

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
# - Add ProxyCheck.io API key (optional, uses mock data if not provided)
# - Update security keys for production
```

### 2. Docker Deployment (Recommended)
```bash
# Start all services with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Services will be available at:
# - IDROCK Security API: http://localhost:8000
# - NexShop E-commerce API: http://localhost:3000
```

### 3. Local Development

#### IDROCK Security Service
```bash
cd idrock-security-service

# Install dependencies
pip install -r requirements.txt

# Run the service
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### NexShop E-commerce Service
```bash
cd nexshop-ecommerce-service

# Install dependencies
npm install

# Run the service
npm run dev
```

## 📚 API Documentation

### IDROCK Security Service
- **Interactive Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

### NexShop E-commerce Service
- **Health Check**: http://localhost:3000/health
- **Authentication**: http://localhost:3000/api/auth
- **Security Integration**: http://localhost:3000/api/security

### Advanced Security Endpoints
- **Device Management**: http://localhost:8000/api/v1/devices
- **Travel Detection**: Advanced impossible travel analysis
- **Hardware Validation**: Real device vs automation tool detection
- **Browser Validation**: Comprehensive automation pattern detection

## 🔐 Authentication

### API Key Authentication

All IDROCK Security Service endpoints require API key authentication using Bearer tokens. This ensures secure communication between client applications and the IDROCK service.

#### Configuration

1. **Environment Variable**: Set `IDROCK_API_KEY` in your `.env` file:
   ```bash
   IDROCK_API_KEY=demo-api-key-12345
   ```

2. **Docker Environment**: The API key is automatically configured in `docker-compose.yml`:
   ```yaml
   environment:
     - IDROCK_API_KEY=${IDROCK_API_KEY:-demo-api-key-12345}
   ```

#### Usage in HTTP Requests

All API requests must include the API key in the Authorization header:

```bash
Authorization: Bearer demo-api-key-12345
```

#### Security Features

- **HTTPBearer Authentication**: FastAPI security scheme for token validation
- **403 Forbidden Response**: Unauthorized requests are blocked with detailed error messages
- **Automatic Token Validation**: Invalid or missing tokens are rejected
- **SDK Integration**: NexShop SDK automatically handles authentication

## 🔧 API Usage Examples

### 1. Identity Verification (Direct IDROCK API)
```bash
curl -X POST "http://localhost:8000/api/v1/identity/verify" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-api-key-12345" \
  -d '{
    "user_id": "user123",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "session_data": {
      "timestamp": "2025-09-07T10:30:00Z"
    },
    "context": {
      "action_type": "login"
    }
  }'
```

### 2. User Registration (NexShop)
```bash
curl -X POST "http://localhost:3000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123",
    "first_name": "Test",
    "last_name": "User"
  }'
```

### 3. Protected Login with Risk Assessment
```bash
curl -X POST "http://localhost:3000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123",
    "deviceFingerprint": "fp_abc123",
    "sessionData": {
      "browser": "Chrome",
      "screen_resolution": "1920x1080"
    }
  }'
```

## 🧪 SDK Integration Examples

### JavaScript SDK (Frontend)
```html
<!-- Include the SDK -->
<script src="/static/js/idrock-sdk.js"></script>

<script>
// Initialize SDK
const idrockSDK = new IDRockSDK({
  apiEndpoint: '/api/security',
  debug: true
});

// Login assessment
async function handleLogin(username, password) {
  try {
    const assessment = await idrockSDK.assessLogin(username);
    
    if (assessment.recommendations.proceed) {
      // Continue with login
      console.log('Login approved');
    } else if (assessment.recommendations.require_additional_auth) {
      // Show additional authentication
      console.log('Additional verification required');
    }
  } catch (error) {
    console.error('Risk assessment failed:', error);
    // Graceful fallback
  }
}
</script>
```

### Node.js SDK (Backend)
```javascript
const { IDRockNodeSDK } = require('./src/services/idrockClient');

// Initialize SDK
const idrockClient = new IDRockNodeSDK({
  baseUrl: 'http://localhost:8000',
  apiKey: process.env.IDROCK_API_KEY
});

// Risk assessment
async function assessRisk(userData) {
  try {
    const assessment = await idrockClient.verifyIdentity(userData);
    
    switch (assessment.risk_level) {
      case 'ALLOW':
        return { proceed: true };
      case 'REVIEW':
        return { proceed: false, requiresReview: true };
      case 'DENY':
        return { proceed: false, blocked: true };
    }
  } catch (error) {
    // Fallback response
    return idrockClient.createFallbackResponse(userData.userId, 'service_error');
  }
}
```

## 📊 Monitoring and Statistics

### Security Statistics
```bash
# Get IDROCK service statistics (requires API key)
curl -H "Authorization: Bearer demo-api-key-12345" \
     "http://localhost:8000/api/v1/identity/stats"

# Get assessment history (requires API key)
curl -H "Authorization: Bearer demo-api-key-12345" \
     "http://localhost:8000/api/v1/identity/history"

# Get NexShop security integration stats
curl "http://localhost:3000/api/security/stats"

# Get authentication statistics
curl "http://localhost:3000/api/auth/stats"
```

### Health Monitoring
```bash
# Check IDROCK service health
curl "http://localhost:8000/health"

# Check NexShop service health
curl "http://localhost:3000/health"

# Check IDROCK integration from NexShop
curl "http://localhost:3000/api/security/health"
```

## 🔒 Advanced Security Features

### Core Security Capabilities
- **API Key Authentication** with HTTPBearer token validation
- **Device Trust Management** with unique constraint prevention of cloning attacks
- **Impossible Travel Detection** using geodesic calculations (>1000 km/h = REVIEW, >2000 km/h = DENY)
- **Hardware Validation System** with minimum CPU/RAM requirements for real devices
- **Browser Automation Detection** with comprehensive pattern matching (Selenium, headless browsers)
- **Advanced Device Fingerprinting** with Canvas, WebGL, Audio signatures
- **Multi-Factor Risk Assessment** with weighted scoring algorithms

### Security Infrastructure
- **IP Reputation Analysis** via ProxyCheck.io integration
- **Risk-based Authentication** with adaptive thresholds
- **Device Access History** tracking for behavioral analysis
- **Comprehensive Audit Logging** for compliance with device events
- **Graceful Fallback** when external services are unavailable
- **JWT Authentication** with secure token management (NexShop)
- **Rate Limiting** and DDoS protection
- **Input Validation** and SQL injection protection
- **403 Forbidden Responses** for unauthorized access attempts
- **Database Constraints** preventing security bypass attempts

## 📈 Risk Assessment Details

### Risk Levels
- **ALLOW (70-100)**: Low risk, proceed normally
- **REVIEW (30-69)**: Medium risk, additional verification required
- **DENY (0-29)**: High risk, block action

### Advanced Risk Factors (Implemented)
- **IP Reputation**: ProxyCheck.io analysis with connection type detection
- **Travel Analysis**: Impossible travel detection using geodesic distance calculations
- **Device Trust**: Unique device fingerprint validation and trust status
- **Hardware Authenticity**: CPU/RAM validation for real computer detection
- **Browser Validation**: Automation tool and headless browser detection
- **Geographic Location**: Country-based risk assessment
- **Proxy/VPN Detection**: Identification of anonymizing services
- **Access Patterns**: Device usage history and behavioral analysis

### Future Enhancements
- CAPTCHA integration (CapJS) for additional verification
- Machine learning risk models with pattern recognition
- Real-time threat intelligence feeds integration
- Advanced behavioral analysis with session tracking

## 🐛 Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check Docker logs
   docker-compose logs

   # Restart services
   docker-compose restart
   ```

2. **Database connection errors**
   ```bash
   # Ensure data directories exist
   mkdir -p idrock-security-service/data
   mkdir -p nexshop-ecommerce-service/data
   ```

3. **IDROCK API not responding**
   ```bash
   # Check service health
   curl http://localhost:8000/health
   
   # Check Docker container status
   docker ps
   ```

4. **ProxyCheck.io API errors**
   - Verify API key in `.env` file
   - Check API quota limits
   - System falls back to mock data if API unavailable

### Debug Mode
```bash
# Enable debug logging
export DEBUG=true
export NODE_ENV=development

# Run services with verbose output
docker-compose up
```

## 📝 Development

### Running Tests
```bash
# IDROCK Security Service
cd idrock-security-service
pytest tests/

# NexShop E-commerce Service
cd nexshop-ecommerce-service
npm test
```

### Code Quality
```bash
# Python linting
cd idrock-security-service
flake8 app/

# JavaScript linting
cd nexshop-ecommerce-service
npm run lint
```

## 📜 License

This project is part of the IDROCK security tool implementation following the comprehensive project plan for IP reputation-based fraud detection.

## 🤝 Contributing

1. Follow secure development best practices
2. Ensure all tests pass
3. Update documentation
4. Follow existing code patterns
5. Test end-to-end integration flows

## 📞 Support

For technical support and questions:
- Check the API documentation at `/docs` endpoints
- Review the comprehensive project plan
- Examine log files for error details
- Use health check endpoints for service status

---

**IDROCK Security Tool v1.0.0-Advanced**
*Comprehensive Security Platform with Advanced Threat Detection*
