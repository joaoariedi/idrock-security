const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const SecurityLog = require('../models/SecurityLog');
const securityMiddleware = require('../middleware/security');

const router = express.Router();

/**
 * User Registration Endpoint
 * 
 * POST /api/auth/register
 */
router.post('/register', [
  body('username').isLength({ min: 3, max: 100 }).isAlphanumeric(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  body('first_name').isLength({ min: 1, max: 100 }),
  body('last_name').isLength({ min: 1, max: 100 }),
  body('phone').optional().matches(/^[+]?[\d\s\-\(\)]{10,20}$/)
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { username, email, password, first_name, last_name, phone } = req.body;

    // Check if user already exists
    const existingUser = await User.findByUsernameOrEmail(username) || 
                         await User.findByUsernameOrEmail(email);
    
    if (existingUser) {
      return res.status(409).json({
        error: 'User already exists',
        message: 'Username or email is already registered'
      });
    }

    // Create new user
    const user = await User.create({
      username,
      email,
      password_hash: password, // Will be hashed by the beforeCreate hook
      first_name,
      last_name,
      phone: phone || null,
      status: 'pending_verification'
    });

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username,
        email: user.email 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: user.toProfile(),
      token,
      expires_in: process.env.JWT_EXPIRES_IN || '24h'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: 'An error occurred during registration'
    });
  }
});

/**
 * User Login Endpoint with IDROCK Security Protection
 * 
 * POST /api/auth/login
 */
router.post('/login', [
  body('username').notEmpty(),
  body('password').notEmpty(),
  // Optional fields from IDROCK JavaScript SDK
  body('deviceFingerprint').optional(),
  body('sessionData').optional(),
  body('additionalData').optional()
], 
securityMiddleware.protectLogin, // IDROCK security middleware
async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { username, password } = req.body;
    const riskAssessment = req.idrockAssessment;

    // Find user by username or email
    const user = await User.findByUsernameOrEmail(username);
    
    if (!user) {
      // Log failed login attempt
      await SecurityLog.logLoginAttempt({
        userId: null,
        ipAddress: securityMiddleware._getClientIP(req),
        userAgent: req.get('User-Agent'),
        success: false,
        riskAssessment: riskAssessment,
        actionTaken: 'user_not_found',
        errorMessage: 'User not found',
        processingTime: req.processingTime || 0
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      });
    }

    // Check if account is locked
    if (user.isLocked()) {
      await SecurityLog.logLoginAttempt({
        userId: user.id,
        ipAddress: securityMiddleware._getClientIP(req),
        userAgent: req.get('User-Agent'),
        success: false,
        riskAssessment: riskAssessment,
        actionTaken: 'account_locked',
        errorMessage: 'Account locked due to failed attempts',
        processingTime: req.processingTime || 0
      });

      return res.status(423).json({
        error: 'Account locked',
        message: 'Account is temporarily locked due to multiple failed login attempts',
        locked_until: user.locked_until
      });
    }

    // Validate password
    const isPasswordValid = await user.validatePassword(password);
    
    if (!isPasswordValid) {
      // Handle failed login
      await user.handleFailedLogin();

      await SecurityLog.logLoginAttempt({
        userId: user.id,
        ipAddress: securityMiddleware._getClientIP(req),
        userAgent: req.get('User-Agent'),
        success: false,
        riskAssessment: riskAssessment,
        actionTaken: 'invalid_password',
        errorMessage: 'Invalid password',
        processingTime: req.processingTime || 0
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      });
    }

    // Check if additional authentication is required based on risk assessment
    if (req.requiresAdditionalAuth && riskAssessment) {
      // Log that additional authentication is required
      await SecurityLog.logLoginAttempt({
        userId: user.id,
        ipAddress: securityMiddleware._getClientIP(req),
        userAgent: req.get('User-Agent'),
        success: false,
        riskAssessment: riskAssessment,
        actionTaken: 'additional_auth_required',
        processingTime: req.processingTime || 0
      });

      return res.status(202).json({
        status: 'additional_verification_required',
        message: 'Additional security verification required',
        verification_methods: ['email', 'sms'],
        security_reasons: req.securityReasons || [],
        risk_assessment: {
          risk_level: riskAssessment.risk_level,
          confidence_score: riskAssessment.confidence_score,
          request_id: riskAssessment.request_id
        },
        // Temporary session token for verification process
        verification_token: jwt.sign(
          { userId: user.id, verification: true },
          process.env.JWT_SECRET,
          { expiresIn: '15m' }
        )
      });
    }

    // Successful login
    await user.updateLoginInfo(securityMiddleware._getClientIP(req));

    // Update user's security score if we have assessment data
    if (riskAssessment && riskAssessment.confidence_score) {
      await user.updateSecurityScore(riskAssessment.confidence_score);
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username,
        email: user.email 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    // Log successful login
    await SecurityLog.logLoginAttempt({
      userId: user.id,
      ipAddress: securityMiddleware._getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: true,
      riskAssessment: riskAssessment,
      actionTaken: 'allowed',
      processingTime: req.processingTime || 0
    });

    // Response includes risk assessment metadata for client awareness
    const response = {
      message: 'Login successful',
      user: user.toProfile(),
      token,
      expires_in: process.env.JWT_EXPIRES_IN || '24h'
    };

    // Include security metadata if available
    if (riskAssessment) {
      response.security = {
        risk_level: riskAssessment.risk_level,
        confidence_score: riskAssessment.confidence_score,
        request_id: riskAssessment.request_id,
        service_available: req.idrockServiceAvailable !== false
      };
    }

    res.json(response);

  } catch (error) {
    console.error('Login error:', error);
    
    // Log error
    if (req.body.username) {
      await SecurityLog.logLoginAttempt({
        userId: null,
        ipAddress: securityMiddleware._getClientIP(req),
        userAgent: req.get('User-Agent'),
        success: false,
        riskAssessment: req.idrockAssessment,
        actionTaken: 'error_fallback',
        errorMessage: error.message,
        processingTime: req.processingTime || 0
      });
    }

    res.status(500).json({
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
});

/**
 * Token Validation Endpoint
 * 
 * GET /api/auth/validate
 */
router.get('/validate', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        error: 'No token provided',
        valid: false
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findByPk(decoded.userId);
    
    if (!user) {
      return res.status(401).json({
        error: 'Invalid token',
        valid: false
      });
    }

    res.json({
      valid: true,
      user: user.toProfile(),
      expires_at: new Date(decoded.exp * 1000)
    });

  } catch (error) {
    res.status(401).json({
      error: 'Invalid token',
      valid: false,
      message: error.message
    });
  }
});

/**
 * Logout Endpoint
 * 
 * POST /api/auth/logout
 */
router.post('/logout', async (req, res) => {
  // Since we're using stateless JWT, logout is handled client-side
  // In production, you might want to implement token blacklisting
  
  res.json({
    message: 'Logged out successfully',
    instructions: 'Please remove the token from client storage'
  });
});

/**
 * Get Authentication Statistics (for monitoring)
 * 
 * GET /api/auth/stats
 */
router.get('/stats', async (req, res) => {
  try {
    // Get IDROCK SDK statistics
    const sdkStats = securityMiddleware.getStats();
    
    // Get basic auth statistics (last 24 hours)
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentLogs = await SecurityLog.findAll({
      where: {
        event_type: 'login_attempt',
        timestamp: {
          [require('sequelize').Op.gte]: oneDayAgo
        }
      }
    });

    const authStats = {
      total_attempts_24h: recentLogs.length,
      successful_logins_24h: recentLogs.filter(log => log.success).length,
      blocked_attempts_24h: recentLogs.filter(log => log.action_taken === 'blocked').length,
      risk_distribution_24h: {
        ALLOW: recentLogs.filter(log => log.risk_level === 'ALLOW').length,
        REVIEW: recentLogs.filter(log => log.risk_level === 'REVIEW').length,
        DENY: recentLogs.filter(log => log.risk_level === 'DENY').length
      }
    };

    res.json({
      auth_stats: authStats,
      idrock_sdk_stats: sdkStats,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      error: 'Failed to retrieve statistics',
      message: error.message
    });
  }
});

module.exports = router;