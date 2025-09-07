const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const idrockConfig = require('../config/idrock');

/**
 * Custom error class for IDROCK API errors
 */
class IDRockAPIError extends Error {
  constructor(message, originalError = null, statusCode = null) {
    super(message);
    this.name = 'IDRockAPIError';
    this.originalError = originalError;
    this.statusCode = statusCode;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * IDROCK Node.js SDK for backend API communication
 * 
 * This SDK is designed for NexShop backend to communicate directly 
 * with the IDROCK FastAPI service for risk assessment.
 */
class IDRockNodeSDK {
  constructor(config = {}) {
    // Merge configuration
    this.config = {
      baseUrl: config.baseUrl || idrockConfig.api.baseUrl,
      apiKey: config.apiKey || idrockConfig.auth.apiKey,
      timeout: config.timeout || idrockConfig.api.timeout,
      retryAttempts: config.retryAttempts || idrockConfig.api.retryAttempts,
      retryDelay: config.retryDelay || idrockConfig.api.retryDelay,
      enableLogging: config.enableLogging !== false
    };

    // Initialize HTTP client
    this.httpClient = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'NexShop-IDRockSDK/1.0.0',
        'Accept': 'application/json'
      }
    });

    // Add authentication if API key is provided
    if (this.config.apiKey) {
      this.httpClient.defaults.headers.common['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    // Setup interceptors for logging and retry logic
    this._setupInterceptors();

    // Track request statistics
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      lastRequestTime: null
    };
  }

  /**
   * Main method to verify identity using IDROCK API
   * 
   * @param {Object} userData - User data for risk assessment
   * @param {string} userData.userId - User identifier
   * @param {string} userData.ipAddress - Client IP address
   * @param {string} userData.userAgent - User agent string
   * @param {string} userData.actionType - Action type (login, checkout, sensitive_action)
   * @param {Object} userData.sessionData - Session data from frontend SDK
   * @param {number} userData.amount - Transaction amount (for checkout)
   * @param {Object} userData.additionalContext - Additional context data
   * @returns {Promise<Object>} Risk assessment response
   */
  async verifyIdentity(userData) {
    const startTime = Date.now();
    
    try {
      // Validate required fields
      this._validateUserData(userData);

      // Prepare API request payload
      const payload = {
        user_id: userData.userId,
        ip_address: userData.ipAddress,
        user_agent: userData.userAgent,
        session_data: {
          timestamp: new Date().toISOString(),
          device_fingerprint: userData.deviceFingerprint,
          ...userData.sessionData
        },
        context: {
          action_type: userData.actionType,
          amount: userData.amount || null,
          additional_context: userData.additionalContext || {}
        }
      };

      // Log request if enabled
      if (this.config.enableLogging) {
        console.log(`[IDRock SDK] Verifying identity for user ${userData.userId}, action: ${userData.actionType}`);
      }

      // Make API request
      const response = await this.httpClient.post(idrockConfig.endpoints.verify, payload);
      
      // Update statistics
      this.stats.totalRequests++;
      this.stats.successfulRequests++;
      this.stats.lastRequestTime = Date.now();
      this._updateAverageResponseTime(Date.now() - startTime);

      // Log successful response
      if (this.config.enableLogging) {
        console.log(`[IDRock SDK] Assessment completed: ${response.data.risk_level} (score: ${response.data.confidence_score})`);
      }

      return response.data;

    } catch (error) {
      this.stats.totalRequests++;
      this.stats.failedRequests++;
      
      // Handle and wrap error
      const wrappedError = this._handleError(error, 'verifyIdentity');
      
      // Log error
      if (this.config.enableLogging) {
        console.error(`[IDRock SDK] Identity verification failed:`, wrappedError.message);
      }
      
      throw wrappedError;
    }
  }

  /**
   * Get assessment history from IDROCK API
   * 
   * @param {string} userId - User identifier
   * @param {Object} filters - History filters
   * @returns {Promise<Object>} History response
   */
  async getAssessmentHistory(userId, filters = {}) {
    try {
      const params = {
        user_id: userId,
        ...filters
      };

      const response = await this.httpClient.get(idrockConfig.endpoints.history, { params });
      
      this.stats.totalRequests++;
      this.stats.successfulRequests++;

      return response.data;

    } catch (error) {
      this.stats.totalRequests++;
      this.stats.failedRequests++;
      
      throw this._handleError(error, 'getAssessmentHistory');
    }
  }

  /**
   * Health check for IDROCK service
   * 
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    try {
      const response = await this.httpClient.get(idrockConfig.endpoints.health);
      
      this.stats.totalRequests++;
      this.stats.successfulRequests++;

      return response.data;

    } catch (error) {
      this.stats.totalRequests++;
      this.stats.failedRequests++;
      
      throw this._handleError(error, 'healthCheck');
    }
  }

  /**
   * Create a fallback response when IDROCK is unavailable
   * 
   * @param {string} userId - User identifier
   * @param {string} reason - Reason for fallback
   * @returns {Object} Fallback risk assessment
   */
  createFallbackResponse(userId, reason = 'service_unavailable') {
    const fallbackConfig = idrockConfig.risk.fallback;
    
    return {
      confidence_score: 50, // Medium confidence for fallback
      risk_level: fallbackConfig.defaultRiskLevel,
      risk_factors: [
        {
          factor: 'system_fallback',
          score: 50,
          weight: 1.0,
          details: `Risk assessment service unavailable: ${reason}`,
          proxycheck_data: { fallback: true }
        }
      ],
      recommendations: [
        {
          action: 'manual_review_recommended',
          priority: 'medium',
          message: 'Manual review recommended due to service unavailability'
        }
      ],
      metadata: {
        processing_time_ms: 0,
        api_version: '1.0.0-fallback',
        request_id: `fallback_${uuidv4().substring(0, 12)}`,
        mvp_scope: 'fallback_mode'
      },
      timestamp: new Date().toISOString(),
      request_id: `fallback_${uuidv4().substring(0, 12)}`,
      api_version: '1.0.0-fallback',
      fallback: true,
      fallback_reason: reason
    };
  }

  /**
   * Get SDK statistics
   * 
   * @returns {Object} SDK usage statistics
   */
  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.totalRequests > 0 
        ? (this.stats.successfulRequests / this.stats.totalRequests * 100).toFixed(2)
        : 0,
      config: {
        baseUrl: this.config.baseUrl,
        timeout: this.config.timeout,
        retryAttempts: this.config.retryAttempts
      }
    };
  }

  /**
   * Validate user data for API request
   * 
   * @private
   * @param {Object} userData - User data to validate
   */
  _validateUserData(userData) {
    const required = ['userId', 'ipAddress', 'userAgent', 'actionType'];
    
    for (const field of required) {
      if (!userData[field]) {
        throw new IDRockAPIError(`Missing required field: ${field}`);
      }
    }

    // Validate action type
    const validActions = ['login', 'checkout', 'sensitive_action'];
    if (!validActions.includes(userData.actionType)) {
      throw new IDRockAPIError(`Invalid action type: ${userData.actionType}. Must be one of: ${validActions.join(', ')}`);
    }

    // Validate IP address format (basic check)
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipRegex.test(userData.ipAddress)) {
      throw new IDRockAPIError(`Invalid IP address format: ${userData.ipAddress}`);
    }
  }

  /**
   * Setup HTTP client interceptors
   * 
   * @private
   */
  _setupInterceptors() {
    // Request interceptor
    this.httpClient.interceptors.request.use(
      (config) => {
        if (this.config.enableLogging) {
          console.log(`[IDRock SDK] ${config.method.toUpperCase()} ${config.url}`);
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor with retry logic
    this.httpClient.interceptors.response.use(
      (response) => response,
      async (error) => {
        const config = error.config;
        
        // Only retry on network errors or 5xx server errors
        const shouldRetry = !config._retryCount && 
                           config._retryCount < this.config.retryAttempts &&
                           (!error.response || error.response.status >= 500);

        if (shouldRetry) {
          config._retryCount = (config._retryCount || 0) + 1;
          
          // Exponential backoff delay
          const delay = this.config.retryDelay * Math.pow(2, config._retryCount - 1);
          await new Promise(resolve => setTimeout(resolve, delay));
          
          return this.httpClient(config);
        }

        return Promise.reject(error);
      }
    );
  }

  /**
   * Handle and wrap errors from HTTP requests
   * 
   * @private
   * @param {Error} error - Original error
   * @param {string} operation - Operation that failed
   * @returns {IDRockAPIError} Wrapped error
   */
  _handleError(error, operation) {
    if (error instanceof IDRockAPIError) {
      return error;
    }

    let message = `Failed to ${operation}`;
    let statusCode = null;

    if (error.response) {
      // HTTP error response
      statusCode = error.response.status;
      const errorData = error.response.data;
      
      if (errorData && errorData.detail) {
        message += `: ${errorData.detail.message || errorData.detail}`;
      } else {
        message += `: HTTP ${statusCode} ${error.response.statusText}`;
      }
    } else if (error.request) {
      // Network error
      message += ': Network error or timeout';
    } else {
      // Other error
      message += `: ${error.message}`;
    }

    return new IDRockAPIError(message, error, statusCode);
  }

  /**
   * Update average response time
   * 
   * @private
   * @param {number} responseTime - Response time in milliseconds
   */
  _updateAverageResponseTime(responseTime) {
    if (this.stats.averageResponseTime === 0) {
      this.stats.averageResponseTime = responseTime;
    } else {
      // Simple moving average
      this.stats.averageResponseTime = (this.stats.averageResponseTime + responseTime) / 2;
    }
  }
}

module.exports = {
  IDRockNodeSDK,
  IDRockAPIError
};