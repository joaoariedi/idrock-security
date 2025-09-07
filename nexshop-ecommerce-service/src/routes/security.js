const express = require('express');
const securityMiddleware = require('../middleware/security');
const SecurityLog = require('../models/SecurityLog');

const router = express.Router();

/**
 * Generic security assessment endpoint
 * Used by IDROCK JavaScript SDK for custom assessments
 * 
 * POST /api/security/assess
 */
router.post('/assess', 
securityMiddleware.assessRisk('generic'),
async (req, res) => {
  try {
    const riskAssessment = req.idrockAssessment;
    
    res.json({
      assessment: riskAssessment,
      action_type: req.riskActionType,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Security assessment error:', error);
    res.status(500).json({
      error: 'Assessment failed',
      message: error.message
    });
  }
});

/**
 * Login-specific assessment endpoint
 * Used by JavaScript SDK for login flows
 * 
 * POST /api/security/login-assess
 */
router.post('/login-assess',
securityMiddleware.assessRisk('login'),
async (req, res) => {
  try {
    const riskAssessment = req.idrockAssessment;
    
    // Return assessment with login-specific recommendations
    res.json({
      assessment: riskAssessment,
      recommendations: {
        proceed: riskAssessment.risk_level === 'ALLOW',
        require_additional_auth: riskAssessment.risk_level === 'REVIEW',
        block: riskAssessment.risk_level === 'DENY',
        reasons: riskAssessment.recommendations?.map(r => r.message) || []
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Login assessment error:', error);
    res.status(500).json({
      error: 'Login assessment failed',
      message: error.message
    });
  }
});

/**
 * Checkout-specific assessment endpoint
 * Used by JavaScript SDK for checkout flows
 * 
 * POST /api/security/checkout-assess
 */
router.post('/checkout-assess',
securityMiddleware.assessRisk('checkout'),
async (req, res) => {
  try {
    const riskAssessment = req.idrockAssessment;
    
    res.json({
      assessment: riskAssessment,
      recommendations: {
        proceed: riskAssessment.risk_level === 'ALLOW',
        require_review: riskAssessment.risk_level === 'REVIEW',
        block: riskAssessment.risk_level === 'DENY',
        reasons: riskAssessment.recommendations?.map(r => r.message) || []
      },
      processing_guidelines: {
        ALLOW: 'Process transaction normally',
        REVIEW: 'Hold for manual review',
        DENY: 'Block transaction and alert security'
      }[riskAssessment.risk_level],
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Checkout assessment error:', error);
    res.status(500).json({
      error: 'Checkout assessment failed',
      message: error.message
    });
  }
});

/**
 * Security statistics endpoint
 * 
 * GET /api/security/stats
 */
router.get('/stats', async (req, res) => {
  try {
    // Get IDROCK SDK statistics
    const sdkStats = securityMiddleware.getStats();
    
    // Get security log statistics
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentLogs = await SecurityLog.findAll({
      where: {
        timestamp: {
          [require('sequelize').Op.gte]: oneDayAgo
        }
      }
    });

    const securityStats = {
      total_assessments_24h: recentLogs.length,
      risk_distribution: {
        ALLOW: recentLogs.filter(log => log.risk_level === 'ALLOW').length,
        REVIEW: recentLogs.filter(log => log.risk_level === 'REVIEW').length,
        DENY: recentLogs.filter(log => log.risk_level === 'DENY').length,
        UNKNOWN: recentLogs.filter(log => log.risk_level === 'UNKNOWN').length
      },
      event_distribution: {
        login_attempt: recentLogs.filter(log => log.event_type === 'login_attempt').length,
        checkout_attempt: recentLogs.filter(log => log.event_type === 'checkout_attempt').length,
        risk_assessment: recentLogs.filter(log => log.event_type === 'risk_assessment').length,
        security_alert: recentLogs.filter(log => log.event_type === 'security_alert').length
      },
      success_rate: recentLogs.length > 0 
        ? ((recentLogs.filter(log => log.success).length / recentLogs.length) * 100).toFixed(2)
        : 0
    };

    res.json({
      security_stats: securityStats,
      idrock_sdk_stats: sdkStats,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Security stats error:', error);
    res.status(500).json({
      error: 'Failed to retrieve security statistics',
      message: error.message
    });
  }
});

/**
 * IDROCK service health check
 * 
 * GET /api/security/health
 */
router.get('/health', async (req, res) => {
  try {
    const healthResponse = await securityMiddleware.idrockClient.healthCheck();
    
    res.json({
      idrock_service: healthResponse,
      nexshop_integration: {
        status: 'healthy',
        sdk_stats: securityMiddleware.getStats(),
        timestamp: new Date().toISOString()
      }
    });
    
  } catch (error) {
    res.status(503).json({
      idrock_service: {
        status: 'unhealthy',
        error: error.message
      },
      nexshop_integration: {
        status: 'degraded',
        fallback_enabled: true,
        timestamp: new Date().toISOString()
      }
    });
  }
});

module.exports = router;