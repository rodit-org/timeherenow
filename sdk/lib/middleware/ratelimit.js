/**
 * Rate limiting middleware
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

/**
 * Rate limiting middleware for API protection
 * Updated to work with express-rate-limit v7.x
 */
const rateLimit = require('express-rate-limit');
const logger = require('../../services/logger');
const { createLogContext, logErrorWithMetrics } = require('../../services/logger');
const { ulid } = require('ulid');

/**
 * Creates a rate limiting middleware with the specified configuration
 * 
 * @param {number} maxRequests - Maximum number of requests allowed per window
 * @param {number} windowMinutes - Time window in minutes for rate limiting
 * @returns {Function} - Express middleware function
 */
function ratelimitmw(maxRequests = 100, windowMinutes = 15) {
  const requestId = ulid();
  const startTime = Date.now();
  
  const baseContext = createLogContext(
    "RateLimitMiddleware",
    "ratelimitmw",
    {
      requestId,
      maxRequests,
      windowMinutes
    }
  );
  
  logger.infoWithContext('Rate limiting middleware initialized', {
    ...baseContext,
    result: 'call',
    reason: 'Rate limiting middleware initialized'
  }); // Function call log

  try {
    const limiter = rateLimit({
      // Define window in milliseconds (converting from minutes)
      windowMs: windowMinutes * 60 * 1000,
      
      // Maximum number of requests per window
      max: maxRequests,
      
      // Return rate limit info in the headers
      standardHeaders: true,
      
      // Disable X-RateLimit-* headers
      legacyHeaders: false,
      
      // Configure how to identify clients when behind a proxy
      // This matches the app.set('trust proxy', 1) configuration
      trustProxy: 1,
      
      // Handler for when the rate limit is exceeded
      handler: (req, res, next, handleroptions) => {
        const exceedRequestId = ulid();
        
        const exceedContext = createLogContext(
          "RateLimitMiddleware",
          "rateLimitExceeded",
          {
            requestId: exceedRequestId,
            ip: req.ip,
            path: req.path,
            method: req.method,
            userId: req.user ? req.user.id : 'anonymous',
            maxRequests: handleroptions.max,
            windowMinutes: handleroptions.windowMs / (60 * 1000)
          }
        );
        
        // Log rate limit exceeded events
        logger.warnWithContext('Rate limit exceeded', {
          ...exceedContext,
          result: 'failure',
          reason: 'Rate limit exceeded'
        });
        // Add metric for rate limit exceeded
        logger.metric("rate_limit_operations", 0, {
          operation: "limit_exceeded",
          path: req.path,
          method: req.method,
          result: "blocked",
          reason: 'Rate limit exceeded'
        });
        
        // Send error response
        res.status(handleroptions.statusCode).json({
          error: 'RateLimitExceeded',
          message: handleroptions.message,
          maxRequests: handleroptions.max,
          windowMinutes: handleroptions.windowMs / (60 * 1000)
        });
      },
      
      // Skip rate limiting for certain requests (optional)
      skip: (req, res) => {
        const skipRequestId = ulid();
        
        const skipContext = createLogContext(
          "RateLimitMiddleware",
          "skipRateLimit",
          {
            requestId: skipRequestId,
            path: req.path,
            method: req.method
          }
        );
        
        // Example: Skip rate limiting for health check endpoints
        const shouldSkip = req.path === '/api/health' || req.path === '/metrics';
        
        if (shouldSkip) {
          logger.debugWithContext('Skipping rate limit for endpoint', skipContext);
          
          // Add metric for skipped rate limiting
          logger.metric("rate_limit_operations", 0, {
            operation: "skip",
            path: req.path,
            method: req.method,
            result: "skipped"
          });
        }
        
        return shouldSkip;
      }
    });
    
    const duration = Date.now() - startTime;
    logger.infoWithContext('Rate limiting middleware created successfully', {
      ...baseContext,
      duration
    });
    
    // Add metric for middleware creation
    logger.metric("rate_limit_operations", duration, {
      operation: "create",
      result: "success"
    });

    return limiter;
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logErrorWithMetrics(
      "Failed to create rate limiting middleware",
      {
        ...baseContext,
        duration
      },
      error,
      "rate_limit_error",
      {
        operation: "create",
        result: "error",
        duration
      }
    );
    
    throw error;
  }
}

module.exports = ratelimitmw;