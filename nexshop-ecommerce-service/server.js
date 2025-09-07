require('dotenv').config();

const createApp = require('./src/config/app');
const { sequelize } = require('./src/config/database');

// Import models to ensure they're registered
require('./src/models/User');
require('./src/models/SecurityLog');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

async function startServer() {
  try {
    // Test database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully');

    // Sync database models (create tables if they don't exist)
    if (NODE_ENV === 'development') {
      await sequelize.sync({ force: true }); // Force recreation to fix foreign key constraints
      console.log('✅ Database models synchronized with force recreation');
    } else {
      await sequelize.sync({ force: false });
      console.log('✅ Database models loaded');
    }

    // Create Express app
    const app = createApp();

    // Start server
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`
🚀 NexShop E-commerce Service Started
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 Server: http://localhost:${PORT}
🌍 Environment: ${NODE_ENV}
📊 Health Check: http://localhost:${PORT}/health
🔐 Security Integration: IDROCK enabled
📚 API Endpoints:
   • Authentication: http://localhost:${PORT}/api/auth
   • Products: http://localhost:${PORT}/api/products
   • Orders: http://localhost:${PORT}/api/orders
   • Security: http://localhost:${PORT}/api/security
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      `);
    });

    // Graceful shutdown handling
    const gracefulShutdown = (signal) => {
      console.log(`\n🛑 Received ${signal}, starting graceful shutdown...`);
      
      server.close(async () => {
        console.log('🔌 HTTP server closed');
        
        try {
          await sequelize.close();
          console.log('💾 Database connection closed');
        } catch (error) {
          console.error('❌ Error closing database connection:', error);
        }
        
        console.log('✅ Graceful shutdown completed');
        process.exit(0);
      });

      // Force shutdown after 10 seconds
      setTimeout(() => {
        console.log('⏰ Forcing shutdown after timeout');
        process.exit(1);
      }, 10000);
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('💥 Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown('unhandledRejection');
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();