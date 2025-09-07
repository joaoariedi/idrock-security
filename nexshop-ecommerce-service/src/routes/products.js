const express = require('express');
const router = express.Router();

// Placeholder product routes for MVP
router.get('/', (req, res) => {
  res.json({
    message: 'Product endpoints - MVP placeholder',
    available_endpoints: [
      'GET /api/products - List products',
      'GET /api/products/:id - Get product details',
      'POST /api/products - Create product (admin)',
      'PUT /api/products/:id - Update product (admin)',
      'DELETE /api/products/:id - Delete product (admin)'
    ]
  });
});

module.exports = router;