/**
 * Performance monitoring middleware
 * Provides request tracing and performance metrics collection
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const logger = require("../../services/logger");
const performanceService = require('../../services/performanceservice');

/**
 * Middleware for monitoring request performance
 * This middleware should be applied before the logging middleware
 * to ensure request IDs and timing are properly set up.
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
const performanceMw = (req, res, next) => {
  // Generate request ID if not already present and make it available for other middleware
  req.requestId = req.requestId || ulid();
  
  // Record the start time and make it available for other middleware
  req.startTime = Date.now();
  
  // Log function call for performance monitoring
  logger.infoWithContext("Performance middleware engaged", {
    component: "PerformanceMiddleware",
    method: req.method,
    path: req.originalUrl,
    requestId: req.requestId,
    clientIP: req.ip,
    result: 'call',
    reason: 'Performance monitoring started'
  });

  // Record the request in the performance monitoring service
  performanceService.recordRequest(req);
  
  // Start a trace for this request
  const traceId = performanceService.startTrace('HTTP Request', {
    method: req.method,
    path: req.originalUrl,
    requestId: req.requestId,
    userAgent: req.get('User-Agent'),
    clientIP: req.ip
  });
  
  // Store the trace ID on the request object for other middleware to use
  req.traceId = traceId;
  
  // Add request classification for better metrics
  req.requestType = classifyRequest(req);
  
  // Capture the original end function
  const originalEnd = res.end;
  
  // Override the end function
  res.end = function(chunk, encoding) {
    // Call the original end function
    originalEnd.call(this, chunk, encoding);
    
    // Calculate request duration
    const duration = Date.now() - req.startTime;
    
    // Store duration for other middleware to use
    req.duration = duration;
    
    // Record standard metrics using the logger.metric function
    const result = (res.statusCode >= 200 && res.statusCode < 300) ? 'success' : 'failure';
    const reason = (result === 'success') ? 'Request completed successfully' : (res.statusMessage || 'Request failed');
    logger.metric('http_request_duration_ms', duration, {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      request_type: req.requestType,
      result,
      reason
    });
    
    // Record error metrics if applicable
    if (res.statusCode >= 400) {
      logger.metric('http_errors_total', 1, {
        method: req.method,
        status: res.statusCode,
        error_type: res.statusCode >= 500 ? 'server_error' : 'client_error',
        request_type: req.requestType,
        result: 'failure',
        reason: res.statusMessage || 'Request failed'
      });
    }
    
    // Complete the trace with request results
    performanceService.completeTrace(traceId, {
      statusCode: res.statusCode,
      success: res.statusCode < 400,
      error: res.statusCode >= 400 ? (res.statusMessage || 'HTTP Error') : null,
      duration,
      responseSize: res._contentLength || 0
    });
    
    // Record specialized metrics based on the request type
    switch (req.requestType) {
      case 'authentication':
        logger.metric('authentication_duration_ms', duration, {
          result,
          reason,
          method: req.method
        });
        break;
      case 'blockchain':
        logger.metric('blockchain_duration_ms', duration, {
          result,
          reason,
          method: req.method
        });
        break;
      case 'rodit':
        logger.metric('rodit_operation_duration_ms', duration, {
          result,
          reason,
          method: req.method
        });
        break;
    }
    
    // Always log errors regardless of load level
    if (res.statusCode >= 500) {
      logger.error("Server error occurred", {
        component: "API",
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        duration,
        requestId: req.requestId,
        traceId
      });
    } else if (res.statusCode >= 400) {
      logger.warn("Client error occurred", {
        component: "API",
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        duration,
        requestId: req.requestId,
        traceId
      });
    }
  };
  
  next();
};

/**
 * Classify the request type for better metrics
 * 
 * @param {Object} req - Express request object
 * @returns {string} Request classification
 */
function classifyRequest(req) {
  const path = req.originalUrl.toLowerCase();
  
  if (path.includes('/api/auth') || path.includes('/login') || path.includes('/token')) {
    return 'authentication';
  } else if (path.includes('/api/blockchain') || path.includes('/smart-contract')) {
    return 'blockchain';
  } else if (path.includes('/api/rodit') || path.includes('/rodit')) {
    return 'rodit';
  } else if (path.includes('/api/user') || path.includes('/profile')) {
    return 'user';
  } else if (path.includes('/health') || path.includes('/status')) {
    return 'system';
  }
  
  return 'general';
}

module.exports = performanceMw;
