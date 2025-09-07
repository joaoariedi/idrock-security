const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

// Route imports
const authRoutes = require('../routes/auth');
const productRoutes = require('../routes/products');
const orderRoutes = require('../routes/orders');
const securityRoutes = require('../routes/security');

// Middleware imports
const errorHandler = require('../middleware/errorHandler');

function createApp() {
  const app = express();

  // Trust proxy for X-Forwarded-For headers (important for rate limiting and IP detection)
  app.set('trust proxy', true);

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false
  }));

  // CORS configuration
  app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
    credentials: process.env.CORS_CREDENTIALS === 'true'
  }));

  // Rate limiting
  const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: {
      error: 'Too many requests from this IP',
      retry_after: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Custom key generator to handle Docker proxy environment properly
    keyGenerator: (req) => {
      // In Docker environment, use forwarded IP or fallback to direct connection
      return req.ip || req.connection.remoteAddress || '127.0.0.1';
    },
    // Skip validation that causes issues with Docker proxy setup
    validate: {
      xForwardedForHeader: false,
      trustProxy: false
    }
  });
  app.use(limiter);

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Logging middleware
  if (process.env.NODE_ENV !== 'test') {
    app.use(morgan('combined'));
  }

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'NexShop E-commerce Service',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    });
  });

  // Root endpoint
  app.get('/', (req, res) => {
    res.json({
      message: 'Welcome to NexShop E-commerce API',
      version: process.env.npm_package_version || '1.0.0',
      endpoints: {
        auth: '/api/auth',
        products: '/api/products',
        orders: '/api/orders',
        security: '/api/security',
        health: '/health'
      },
      documentation: '/api/docs'
    });
  });

  // API Routes
  app.use('/api/auth', authRoutes);
  app.use('/api/products', productRoutes);
  app.use('/api/orders', orderRoutes);
  app.use('/api/security', securityRoutes);

  // Static files (for SDK and frontend assets)
  app.use('/static', express.static('src/public'));

  // 404 handler
  app.use('*', (req, res) => {
    res.status(404).json({
      error: 'Not Found',
      message: `Route ${req.originalUrl} not found`,
      available_endpoints: [
        '/api/auth',
        '/api/products', 
        '/api/orders',
        '/api/security',
        '/health'
      ]
    });
  });

  // Global error handler
  app.use(errorHandler);

  return app;
}

module.exports = createApp;