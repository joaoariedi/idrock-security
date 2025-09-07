module.exports = {
  // IDROCK API Configuration
  api: {
    baseUrl: process.env.IDROCK_API_URL || 'http://localhost:8000',
    version: 'v1',
    timeout: parseInt(process.env.IDROCK_TIMEOUT) || 5000,
    retryAttempts: 3,
    retryDelay: 1000
  },

  // Authentication
  auth: {
    apiKey: process.env.IDROCK_API_KEY,
    bearerToken: process.env.IDROCK_BEARER_TOKEN
  },

  // Risk Assessment Configuration
  risk: {
    // Risk level thresholds (matching IDROCK service)
    thresholds: {
      allow: 70,
      review: 30,
      deny: 0
    },
    
    // Default actions for each risk level
    actions: {
      ALLOW: {
        proceed: true,
        additionalAuth: false,
        monitoring: 'standard'
      },
      REVIEW: {
        proceed: false,
        additionalAuth: true,
        monitoring: 'enhanced'
      },
      DENY: {
        proceed: false,
        additionalAuth: false,
        monitoring: 'alert'
      }
    },

    // Fallback configuration when IDROCK is unavailable
    fallback: {
      enabled: true,
      defaultRiskLevel: 'REVIEW',
      allowProceed: true,
      logFailures: true
    }
  },

  // Integration Settings
  integration: {
    // Enable/disable IDROCK integration
    enabled: process.env.IDROCK_ENABLED !== 'false',
    
    // SDK Configuration
    sdk: {
      enableFingerprintCollection: true,
      enableSessionTracking: true,
      enableBehaviorAnalysis: false, // MVP: disabled
      debugMode: process.env.NODE_ENV === 'development'
    },

    // Caching (if implemented)
    cache: {
      enabled: false, // MVP: disabled
      ttl: 300, // 5 minutes
      maxSize: 1000
    },

    // Logging and monitoring
    logging: {
      logRequests: true,
      logResponses: true,
      logErrors: true,
      includeUserData: process.env.NODE_ENV === 'development'
    }
  },

  // Feature flags for progressive rollout
  features: {
    loginProtection: true,
    checkoutProtection: true,
    sensitiveActionProtection: false, // MVP: disabled
    realTimeScoring: true,
    historicalAnalysis: false, // MVP: disabled
    adaptiveThresholds: false // MVP: disabled
  },

  // API endpoints
  endpoints: {
    verify: '/api/v1/identity/verify',
    history: '/api/v1/identity/history',
    health: '/health'
  }
};