const { Sequelize } = require('sequelize');
const path = require('path');

// Database configuration
const config = {
  development: {
    dialect: 'sqlite',
    storage: path.join(__dirname, '../../nexshop.db'),
    logging: process.env.DATABASE_LOGGING === 'true' ? console.log : false,
    define: {
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    }
  },
  test: {
    dialect: 'sqlite',
    storage: ':memory:',
    logging: false,
    define: {
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    }
  },
  production: {
    dialect: 'sqlite',
    storage: process.env.DATABASE_PATH || './nexshop_prod.db',
    logging: false,
    define: {
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    },
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
};

const environment = process.env.NODE_ENV || 'development';
const sequelize = new Sequelize(config[environment]);

module.exports = {
  sequelize,
  Sequelize
};