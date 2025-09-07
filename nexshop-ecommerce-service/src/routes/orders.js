const express = require('express');
const { body, validationResult } = require('express-validator');
const securityMiddleware = require('../middleware/security');

const router = express.Router();

/**
 * Checkout endpoint with IDROCK security protection
 * 
 * POST /api/orders/checkout
 */
router.post('/checkout', [
  body('totalAmount').isFloat({ min: 0 }),
  body('paymentMethod').isIn(['credit_card', 'debit_card', 'paypal', 'apple_pay']),
  body('items').isArray({ min: 1 }),
  // Optional IDROCK SDK data
  body('deviceFingerprint').optional(),
  body('sessionData').optional(),
  body('additionalData').optional()
], 
securityMiddleware.protectCheckout, // IDROCK security middleware
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

    const { totalAmount, paymentMethod, items } = req.body;
    const riskAssessment = req.idrockAssessment;

    // Handle risk-based responses
    if (req.requiresReview) {
      return res.status(202).json({
        status: 'review_required',
        message: 'Transaction requires additional review',
        security_reasons: req.securityReasons || [],
        risk_assessment: riskAssessment ? {
          risk_level: riskAssessment.risk_level,
          confidence_score: riskAssessment.confidence_score,
          request_id: riskAssessment.request_id
        } : null,
        next_steps: [
          'Transaction will be reviewed manually',
          'You will receive confirmation within 24 hours',
          'Payment will not be charged until approval'
        ]
      });
    }

    // MVP: Simulate successful checkout
    const orderId = `order_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const response = {
      message: 'Checkout successful',
      order: {
        id: orderId,
        status: 'confirmed',
        total_amount: totalAmount,
        payment_method: paymentMethod,
        items: items,
        created_at: new Date().toISOString()
      }
    };

    // Include security metadata
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
    console.error('Checkout error:', error);
    res.status(500).json({
      error: 'Checkout failed',
      message: 'An error occurred during checkout'
    });
  }
});

// Placeholder order routes
router.get('/', (req, res) => {
  res.json({
    message: 'Order endpoints - MVP placeholder',
    available_endpoints: [
      'POST /api/orders/checkout - Process checkout with security',
      'GET /api/orders - List user orders',
      'GET /api/orders/:id - Get order details',
      'PUT /api/orders/:id/cancel - Cancel order'
    ]
  });
});

module.exports = router;