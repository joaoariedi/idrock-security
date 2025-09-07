const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const SecurityLog = sequelize.define('SecurityLog', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  
  // Event identification
  event_type: {
    type: DataTypes.STRING(50),
    allowNull: false,
    validate: {
      isIn: [['login_attempt', 'checkout_attempt', 'risk_assessment', 'security_alert', 'auth_failure']]
    }
  },
  
  // User and session information
  user_id: {
    type: DataTypes.UUID,
    allowNull: true // Can be null for anonymous events - no foreign key constraint to avoid DB issues
  },
  
  session_id: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  
  // Request context
  ip_address: {
    type: DataTypes.STRING(45), // IPv6 compatible
    allowNull: false
  },
  
  user_agent: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  
  // IDROCK assessment data
  idrock_request_id: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  
  risk_level: {
    type: DataTypes.ENUM('ALLOW', 'REVIEW', 'DENY', 'UNKNOWN'),
    allowNull: true
  },
  
  confidence_score: {
    type: DataTypes.INTEGER,
    allowNull: true,
    validate: {
      min: 0,
      max: 100
    }
  },
  
  // Event details
  action_taken: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      isIn: [['allowed', 'blocked', 'requires_review', 'additional_auth_required', 'error_fallback', 'assessed', 'alert_generated']]
    }
  },
  
  success: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  },
  
  // Additional data
  event_data: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: {}
  },
  
  // Error information
  error_message: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  
  error_code: {
    type: DataTypes.STRING(50),
    allowNull: true
  },
  
  // Processing metadata
  processing_time_ms: {
    type: DataTypes.INTEGER,
    allowNull: true,
    validate: {
      min: 0
    }
  },
  
  // Timestamps
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'security_logs',
  timestamps: false, // Using custom timestamp field
  
  // Indexes for performance and querying
  indexes: [
    { fields: ['user_id'] },
    { fields: ['event_type'] },
    { fields: ['ip_address'] },
    { fields: ['risk_level'] },
    { fields: ['timestamp'] },
    { fields: ['success'] },
    { fields: ['idrock_request_id'] },
    { fields: ['user_id', 'timestamp'] }, // Composite index for user timeline
    { fields: ['event_type', 'timestamp'] } // Composite index for event analysis
  ]
});

// Class methods for creating specific log types
SecurityLog.logLoginAttempt = async function(data) {
  const {
    userId,
    ipAddress,
    userAgent,
    success,
    riskAssessment,
    actionTaken,
    errorMessage,
    processingTime
  } = data;
  
  return await this.create({
    event_type: 'login_attempt',
    user_id: userId || null,
    ip_address: ipAddress,
    user_agent: userAgent,
    idrock_request_id: riskAssessment?.request_id || null,
    risk_level: riskAssessment?.risk_level || 'UNKNOWN',
    confidence_score: riskAssessment?.confidence_score || null,
    action_taken: actionTaken,
    success: success,
    event_data: {
      risk_factors: riskAssessment?.risk_factors || [],
      recommendations: riskAssessment?.recommendations || []
    },
    error_message: errorMessage,
    processing_time_ms: processingTime,
    timestamp: new Date()
  });
};

SecurityLog.logCheckoutAttempt = async function(data) {
  const {
    userId,
    ipAddress,
    userAgent,
    orderAmount,
    success,
    riskAssessment,
    actionTaken,
    errorMessage,
    processingTime
  } = data;
  
  return await this.create({
    event_type: 'checkout_attempt',
    user_id: userId,
    ip_address: ipAddress,
    user_agent: userAgent,
    idrock_request_id: riskAssessment?.request_id || null,
    risk_level: riskAssessment?.risk_level || 'UNKNOWN',
    confidence_score: riskAssessment?.confidence_score || null,
    action_taken: actionTaken,
    success: success,
    event_data: {
      order_amount: orderAmount,
      risk_factors: riskAssessment?.risk_factors || [],
      recommendations: riskAssessment?.recommendations || []
    },
    error_message: errorMessage,
    processing_time_ms: processingTime,
    timestamp: new Date()
  });
};

SecurityLog.logRiskAssessment = async function(data) {
  const {
    userId,
    ipAddress,
    userAgent,
    riskAssessment,
    processingTime,
    success = true
  } = data;
  
  return await this.create({
    event_type: 'risk_assessment',
    user_id: userId || null,
    ip_address: ipAddress,
    user_agent: userAgent,
    idrock_request_id: riskAssessment?.request_id || null,
    risk_level: riskAssessment?.risk_level || 'UNKNOWN',
    confidence_score: riskAssessment?.confidence_score || null,
    action_taken: 'assessed',
    success: success,
    event_data: {
      risk_factors: riskAssessment?.risk_factors || [],
      recommendations: riskAssessment?.recommendations || [],
      metadata: riskAssessment?.metadata || {}
    },
    processing_time_ms: processingTime,
    timestamp: new Date()
  });
};

SecurityLog.logSecurityAlert = async function(data) {
  const {
    userId,
    ipAddress,
    userAgent,
    alertType,
    alertMessage,
    riskAssessment,
    additionalData
  } = data;
  
  return await this.create({
    event_type: 'security_alert',
    user_id: userId || null,
    ip_address: ipAddress,
    user_agent: userAgent,
    idrock_request_id: riskAssessment?.request_id || null,
    risk_level: riskAssessment?.risk_level || 'DENY',
    confidence_score: riskAssessment?.confidence_score || null,
    action_taken: 'alert_generated',
    success: true,
    event_data: {
      alert_type: alertType,
      alert_message: alertMessage,
      ...additionalData
    },
    timestamp: new Date()
  });
};

// Instance methods
SecurityLog.prototype.toJSON = function() {
  return {
    id: this.id,
    event_type: this.event_type,
    user_id: this.user_id,
    ip_address: this.ip_address,
    risk_level: this.risk_level,
    confidence_score: this.confidence_score,
    action_taken: this.action_taken,
    success: this.success,
    timestamp: this.timestamp,
    processing_time_ms: this.processing_time_ms,
    event_data: this.event_data
  };
};

module.exports = SecurityLog;