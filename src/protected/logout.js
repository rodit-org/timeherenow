/**
 * logout.js - API routes for user logout
 * 
 * This module provides Express routes for user logout, delegating to
 * the centralized session management in sessionroutes.js.
 * 
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const express = require("express");
const router = express.Router();
const { logger } = require("@rodit/rodit-auth-be");
const { createLogContext, logErrorWithMetrics } = logger;
const { ulid } = require("ulid");

// Import authentication middleware
const { authenticate_apicall } = require("@rodit/rodit-auth-be");

// Handling logout request - now processes logout directly instead of redirecting
router.post("/logout", authenticate_apicall, (req, res) => {
  const requestId = req.headers['x-request-id'] || ulid();
  const startTime = Date.now();
  req.logAction = "logout-attempt";
  
  const baseContext = createLogContext({
    requestId,
    component: 'LogoutRoutes',
    method: 'logout',
    endpoint: '/api/logout',
    httpMethod: req.method,
    userId: req.user?.id,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    headers: Object.keys(req.headers)
  });
  
  logger.debugWithContext("Processing logout request directly", baseContext);
  
  try {
    // Check if the logout_client method exists on the centralized client
    if (!req.app.locals.roditClient) {
      logger.errorWithContext("Authentication service unavailable", baseContext);
      return res.status(503).json({ 
        error: 'Authentication service unavailable',
        requestId
      });
    }
    
    if (typeof req.app.locals.roditClient.logout_client !== 'function') {
      logger.errorWithContext("logout_client method not available", {
        ...baseContext,
        availableMethods: Object.getOwnPropertyNames(req.app.locals.roditClient).filter(name => typeof req.app.locals.roditClient[name] === 'function')
      });
      return res.status(503).json({ 
        error: 'Logout service unavailable',
        details: 'logout_client method not found on authentication service',
        requestId
      });
    }
    
    // Process logout directly using the centralized RoditClient
    logger.infoWithContext("Delegating to centralized logout_client", baseContext);
    return req.app.locals.roditClient.logout_client(req, res);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logErrorWithMetrics(
      'Error processing logout request',
      {
        ...baseContext,
        duration
      },
      error,
      'auth_error',
      {
        operation: 'logout_direct',
        result: 'error',
        duration
      }
    );
    
    res.status(500).json({
      error: 'Failed to process logout request',
      message: error.message,
      requestId
    });
  }
});

module.exports = router;
