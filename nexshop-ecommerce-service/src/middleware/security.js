const { IDRockNodeSDK, IDRockAPIError } = require('../services/idrockClient');
const SecurityLog = require('../models/SecurityLog');
const idrockConfig = require('../config/idrock');
const User = require('../models/User');

/**
 * IDROCK Security Middleware for NexShop
 * 
 * This middleware integrates with IDROCK security service to provide
 * real-time fraud risk assessment for critical user actions.
 */
class SecurityMiddleware {
  constructor() {
    // Initialize IDROCK SDK client
    this.idrockClient = new IDRockNodeSDK();
    
    // Configuration from idrock config
    this.config = idrockConfig;
    
    // Bind methods to preserve context
    this.protectLogin = this.protectLogin.bind(this);
    this.protectCheckout = this.protectCheckout.bind(this);
    this.assessRisk = this.assessRisk.bind(this);
  }

  /**
   * Middleware for login protection
   * 
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object  
   * @param {Function} next - Next middleware function
   */
  async protectLogin(req, res, next) {
    const startTime = Date.now();
    let riskAssessment = null;

    try {
      // Skip if IDROCK integration is disabled
      if (!this.config.integration.enabled) {
        return next();
      }

      // Extract user data from request
      const userData = this._extractLoginUserData(req);
      
      // Perform risk assessment
      riskAssessment = await this.idrockClient.verifyIdentity(userData);
      
      // Add assessment to request for downstream processing
      req.idrockAssessment = riskAssessment;
      req.processingTime = Date.now() - startTime;
      
      // Log the assessment
      try {
        const actualUserId = await this._resolveUserId(userData.userId);
        await SecurityLog.logRiskAssessment({
          userId: actualUserId,
          ipAddress: userData.ipAddress,
          userAgent: userData.userAgent,
          riskAssessment: riskAssessment,
          processingTime: req.processingTime
        });
        console.log('[Security Middleware] Risk assessment logged:', riskAssessment.risk_level);
      } catch (logError) {
        console.warn('[Security Middleware] Failed to log risk assessment:', logError.message);
        // Continue with the request even if logging fails
      }

      // Handle risk levels according to configuration
      switch (riskAssessment.risk_level) {
        case 'DENY':
          // Block the login attempt
          try {
            const actualUserId = await this._resolveUserId(userData.userId);
            await SecurityLog.logLoginAttempt({
              userId: actualUserId,
              ipAddress: userData.ipAddress,
              userAgent: userData.userAgent,
              success: false,
              riskAssessment: riskAssessment,
              actionTaken: 'blocked',
              processingTime: req.processingTime
            });
            console.log('[Security Middleware] Login attempt blocked and logged');
          } catch (logError) {
            console.warn('[Security Middleware] Failed to log login attempt:', logError.message);
          }

          return res.status(403).json({
            error: 'Login blocked for security reasons',
            code: 'SECURITY_BLOCK',
            riskLevel: riskAssessment.risk_level,
            requestId: riskAssessment.request_id,
            message: 'Your login attempt has been blocked due to security concerns. Please contact support if you believe this is an error.'
          });

        case 'REVIEW':
          // Flag for additional authentication
          req.requiresAdditionalAuth = true;
          req.securityReasons = riskAssessment.recommendations.map(r => r.message);
          break;

        case 'ALLOW':
          // Continue with normal flow
          break;
      }

      next();

    } catch (error) {
      // Handle IDROCK service errors gracefully
      const processingTime = Date.now() - startTime;
      
      if (error instanceof IDRockAPIError) {
        console.warn('[Security Middleware] IDROCK API error:', error.message);
      } else {
        console.error('[Security Middleware] Unexpected error:', error);
      }

      // Use fallback response if configured
      if (this.config.risk.fallback.enabled) {
        req.idrockAssessment = this.idrockClient.createFallbackResponse(
          req.body.username || 'unknown',
          'service_error'
        );
        req.idrockServiceAvailable = false;
        req.processingTime = processingTime;

        // Log the fallback
        await SecurityLog.logRiskAssessment({
          userId: req.body.username || null,
          ipAddress: this._getClientIP(req),
          userAgent: req.get('User-Agent'),
          riskAssessment: req.idrockAssessment,
          processingTime: processingTime,
          success: false
        });

        if (this.config.risk.fallback.allowProceed) {
          // Proceed with fallback assessment
          req.requiresAdditionalAuth = true;
          return next();
        }
      }

      // If fallback is not enabled or configured to block, return error
      return res.status(503).json({
        error: 'Security service temporarily unavailable',
        code: 'SERVICE_UNAVAILABLE',
        message: 'Please try again in a few minutes'
      });
    }
  }

  /**
   * Middleware for checkout protection
   * 
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  async protectCheckout(req, res, next) {
    const startTime = Date.now();
    let riskAssessment = null;

    try {
      // Skip if IDROCK integration is disabled
      if (!this.config.integration.enabled) {
        return next();
      }

      // Extract checkout data from request
      const userData = this._extractCheckoutUserData(req);
      
      // Perform risk assessment
      riskAssessment = await this.idrockClient.verifyIdentity(userData);
      
      // Add assessment to request
      req.idrockAssessment = riskAssessment;
      req.processingTime = Date.now() - startTime;

      // Log the assessment
      await SecurityLog.logRiskAssessment({
        userId: userData.userId,
        ipAddress: userData.ipAddress,
        userAgent: userData.userAgent,
        riskAssessment: riskAssessment,
        processingTime: req.processingTime
      });

      // Handle risk levels for checkout
      switch (riskAssessment.risk_level) {
        case 'DENY':
          // Block the transaction
          await SecurityLog.logCheckoutAttempt({
            userId: userData.userId,
            ipAddress: userData.ipAddress,
            userAgent: userData.userAgent,
            orderAmount: userData.amount,
            success: false,
            riskAssessment: riskAssessment,
            actionTaken: 'blocked',
            processingTime: req.processingTime
          });

          return res.status(403).json({
            error: 'Transaction blocked for security reasons',
            code: 'TRANSACTION_BLOCKED',
            riskLevel: riskAssessment.risk_level,
            requestId: riskAssessment.request_id,
            message: 'Your transaction has been blocked due to security concerns. Please contact support.'
          });

        case 'REVIEW':
          // Flag for manual review or additional verification
          req.requiresReview = true;
          req.securityReasons = riskAssessment.recommendations.map(r => r.message);
          break;

        case 'ALLOW':
          // Continue with normal checkout flow
          break;
      }

      next();

    } catch (error) {
      // Handle errors with checkout fallback
      const processingTime = Date.now() - startTime;
      
      console.error('[Security Middleware] Checkout protection error:', error);

      // Fallback for checkout is more conservative
      if (this.config.risk.fallback.enabled) {
        req.idrockAssessment = this.idrockClient.createFallbackResponse(
          req.user?.id || 'unknown',
          'checkout_service_error'
        );
        req.idrockServiceAvailable = false;
        req.processingTime = processingTime;

        // For checkout, require review when service is down
        req.requiresReview = true;
        req.securityReasons = ['Security service temporarily unavailable - manual review required'];

        return next();
      }

      // Block checkout if no fallback
      return res.status(503).json({
        error: 'Security verification required',
        code: 'SECURITY_VERIFICATION_REQUIRED',
        message: 'Transaction cannot be processed at this time. Please try again later.'
      });
    }
  }

  /**
   * Generic risk assessment middleware
   * 
   * @param {string} actionType - Type of action to assess
   * @returns {Function} Middleware function
   */
  assessRisk(actionType) {
    return async (req, res, next) => {
      try {
        if (!this.config.integration.enabled) {
          return next();
        }

        const userData = {
          userId: req.user?.id || req.body.userId || 'anonymous',
          ipAddress: this._getClientIP(req),
          userAgent: req.get('User-Agent') || 'unknown',
          actionType: actionType,
          deviceFingerprint: req.body.deviceFingerprint,
          sessionData: req.body.sessionData,
          additionalContext: req.body.additionalContext || {}
        };

        const riskAssessment = await this.idrockClient.verifyIdentity(userData);
        
        req.idrockAssessment = riskAssessment;
        req.riskActionType = actionType;

        next();

      } catch (error) {
        console.error('[Security Middleware] Risk assessment error:', error);
        
        // Proceed with fallback
        req.idrockAssessment = this.idrockClient.createFallbackResponse(
          userData?.userId || 'unknown',
          'generic_assessment_error'
        );
        
        next();
      }
    };
  }

  /**
   * Extract user data for login assessment
   * 
   * @private
   * @param {Object} req - Express request object
   * @returns {Object} User data for assessment
   */
  _extractLoginUserData(req) {
    return {
      userId: req.body.username || req.body.email || 'anonymous',
      ipAddress: this._getClientIP(req),
      userAgent: req.get('User-Agent') || 'unknown',
      actionType: 'login',
      deviceFingerprint: req.body.deviceFingerprint,
      sessionData: req.body.sessionData || {},
      additionalContext: {
        loginAttempt: true,
        timestamp: new Date().toISOString(),
        ...req.body.additionalData
      }
    };
  }

  /**
   * Extract user data for checkout assessment
   * 
   * @private
   * @param {Object} req - Express request object
   * @returns {Object} User data for assessment
   */
  _extractCheckoutUserData(req) {
    return {
      userId: req.user?.id || req.body.userId || 'unknown',
      ipAddress: this._getClientIP(req),
      userAgent: req.get('User-Agent') || 'unknown',
      actionType: 'checkout',
      amount: req.body.totalAmount || req.body.amount || 0,
      deviceFingerprint: req.body.deviceFingerprint,
      sessionData: req.body.sessionData || {},
      additionalContext: {
        checkoutAttempt: true,
        paymentMethod: req.body.paymentMethod,
        itemCount: req.body.itemCount || 1,
        timestamp: new Date().toISOString(),
        ...req.body.additionalData
      }
    };
  }

  /**
   * Extract client IP address from request
   * 
   * @private
   * @param {Object} req - Express request object
   * @returns {string} Client IP address
   */
  _getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           '127.0.0.1';
  }

  /**
   * Resolve username/email to user UUID
   * 
   * @private
   * @param {string} identifier - Username or email
   * @returns {Promise<string|null>} User UUID or null
   */
  async _resolveUserId(identifier) {
    if (!identifier || identifier === 'anonymous') {
      return null;
    }
    
    try {
      const user = await User.findByUsernameOrEmail(identifier);
      return user ? user.id : null;
    } catch (error) {
      console.warn('[Security Middleware] Failed to resolve user ID:', error.message);
      return null;
    }
  }

  /**
   * Get SDK statistics
   * 
   * @returns {Object} SDK statistics
   */
  getStats() {
    return this.idrockClient.getStats();
  }
}

// Create singleton instance
const securityMiddleware = new SecurityMiddleware();

module.exports = securityMiddleware;