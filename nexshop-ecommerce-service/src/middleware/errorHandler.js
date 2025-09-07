/**
 * Global error handler middleware for NexShop
 */
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Default error
  let error = {
    status: 500,
    message: 'Internal Server Error',
    code: 'INTERNAL_ERROR'
  };

  // Validation errors
  if (err.name === 'ValidationError') {
    error = {
      status: 400,
      message: 'Validation Error',
      code: 'VALIDATION_ERROR',
      details: err.errors || err.message
    };
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = {
      status: 401,
      message: 'Invalid token',
      code: 'INVALID_TOKEN'
    };
  }

  // Sequelize errors
  if (err.name === 'SequelizeValidationError') {
    error = {
      status: 400,
      message: 'Database validation error',
      code: 'DATABASE_VALIDATION_ERROR',
      details: err.errors.map(e => ({ field: e.path, message: e.message }))
    };
  }

  // IDROCK API errors
  if (err.name === 'IDRockAPIError') {
    error = {
      status: 503,
      message: 'Security service error',
      code: 'SECURITY_SERVICE_ERROR',
      details: err.message
    };
  }

  res.status(error.status).json({
    error: error.message,
    code: error.code,
    ...(error.details && { details: error.details }),
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    method: req.method
  });
};

module.exports = errorHandler;