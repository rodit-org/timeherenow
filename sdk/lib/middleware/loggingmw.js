/**
 * Request logging middleware
 * Provides standardized request/response logging
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const logger = require("../../services/logger");
const config = require('../../services/configsdk');

/**
 * Middleware for logging requests and responses
 * This middleware should be applied after the performance middleware
 * to leverage the request ID and timing information.
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
const loggingmw = (req, res, next) => {
  // Ensure we have a request ID (should be set by performance middleware)
  if (!req.requestId) {
    const { ulid } = require("ulid");
    req.requestId = ulid();
  }

  // Capture the original end function
  const originalEnd = res.end;

  // Override the end function
  res.end = function (chunk, encoding) {
    // Call the original end function
    originalEnd.call(this, chunk, encoding);

    // Now log after the response has been sent
    // Use duration from performance middleware if available
    const duration = req.duration || (req.startTime ? Date.now() - req.startTime : null);
    
    // Standard request result log entry
    const result = (res.statusCode >= 200 && res.statusCode < 300) ? 'success' : 'failure';
    const reason = res.statusMessage || (result === 'success' ? 'Request completed successfully' : 'Request failed');
    logger.infoWithContext("Request completed", {
      component: "API",
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      requestId: req.requestId,
      userId: req.user ? req.user.id : undefined,
      authenticated: !!req.user,
      clientIP: req.ip,
      duration,
      result,
      reason
    });
    // Emit a metric for request completion
    logger.metric("api_request_duration_ms", duration, {
      component: "API",
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      requestId: req.requestId,
      userId: req.user ? req.user.id : undefined,
      result,
      reason
    });
  };

  // Log the incoming request (function call)
  logger.info("Request received", {
    component: "API",
    method: req.method,
    url: req.originalUrl,
    clientIP: req.ip,
    requestId: req.requestId,
    timestamp: new Date().toISOString(),
    result: 'call',
    reason: 'Request received'
  });

  next();
};

module.exports = loggingmw;
