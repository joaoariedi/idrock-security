const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const bcrypt = require('bcryptjs');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  
  // Authentication fields
  username: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
    validate: {
      len: [3, 100],
      isAlphanumeric: true
    }
  },
  
  email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  
  password_hash: {
    type: DataTypes.STRING(255),
    allowNull: false,
    field: 'password_hash'
  },
  
  // Profile information
  first_name: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      len: [1, 100]
    }
  },
  
  last_name: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      len: [1, 100]
    }
  },
  
  phone: {
    type: DataTypes.STRING(20),
    allowNull: true,
    validate: {
      is: /^[+]?[\d\s\-\(\)]{10,20}$/
    }
  },
  
  // Account status
  status: {
    type: DataTypes.ENUM('active', 'inactive', 'suspended', 'pending_verification'),
    defaultValue: 'pending_verification',
    allowNull: false
  },
  
  email_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  // Security-related fields
  last_login_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  last_login_ip: {
    type: DataTypes.STRING(45), // IPv6 compatible
    allowNull: true
  },
  
  failed_login_attempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false
  },
  
  locked_until: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  // IDROCK integration fields
  security_score_avg: {
    type: DataTypes.INTEGER,
    allowNull: true,
    validate: {
      min: 0,
      max: 100
    }
  },
  
  risk_level_history: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: []
  },
  
  // Timestamps handled by Sequelize
  created_at: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  
  updated_at: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'users',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for performance
  indexes: [
    { fields: ['username'] },
    { fields: ['email'] },
    { fields: ['status'] },
    { fields: ['last_login_at'] }
  ],
  
});

// Instance methods
User.prototype.validatePassword = async function(password) {
  return await bcrypt.compare(password, this.password_hash);
};

User.prototype.updateLoginInfo = async function(ipAddress) {
  this.last_login_at = new Date();
  this.last_login_ip = ipAddress;
  this.failed_login_attempts = 0;
  this.locked_until = null;
  await this.save();
};

User.prototype.handleFailedLogin = async function() {
  this.failed_login_attempts += 1;
  
  // Lock account after 5 failed attempts for 15 minutes
  if (this.failed_login_attempts >= 5) {
    this.locked_until = new Date(Date.now() + 15 * 60 * 1000);
  }
  
  await this.save();
};

User.prototype.isLocked = function() {
  return this.locked_until && new Date() < this.locked_until;
};

User.prototype.updateSecurityScore = async function(newScore) {
  const history = this.risk_level_history || [];
  history.push({
    score: newScore,
    timestamp: new Date().toISOString()
  });
  
  // Keep only last 10 scores
  this.risk_level_history = history.slice(-10);
  
  // Calculate average
  const scores = history.map(h => h.score);
  this.security_score_avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  
  await this.save();
};

User.prototype.toProfile = function() {
  return {
    id: this.id,
    username: this.username,
    email: this.email,
    first_name: this.first_name,
    last_name: this.last_name,
    phone: this.phone,
    status: this.status,
    email_verified: this.email_verified,
    last_login_at: this.last_login_at,
    security_score_avg: this.security_score_avg,
    created_at: this.created_at
  };
};

// Class methods
User.hashPassword = async function(password) {
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  return await bcrypt.hash(password, saltRounds);
};

User.findByUsernameOrEmail = async function(identifier) {
  return await this.findOne({
    where: {
      [sequelize.Sequelize.Op.or]: [
        { username: identifier },
        { email: identifier }
      ]
    }
  });
};

// Hooks
User.beforeCreate(async (user) => {
  if (user.password_hash && !user.password_hash.startsWith('$2')) {
    user.password_hash = await User.hashPassword(user.password_hash);
  }
});

User.beforeUpdate(async (user) => {
  if (user.changed('password_hash') && !user.password_hash.startsWith('$2')) {
    user.password_hash = await User.hashPassword(user.password_hash);
  }
});

module.exports = User;