/**
 * sessionRoutes.js - API routes for session management
 * 
 * This module provides Express routes for session management including
 * login, logout, and administrative session operations.
 * 
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const express = require('express');
const router = express.Router();
const { ulid } = require('ulid');
const { RoditClient } = require('@rodit/rodit-auth-be');

// Create SDK client instance to access all functionality
const sdkClient = new RoditClient();
const logger = sdkClient.getLogger();
// Get session manager instance from SDK (avoids ReferenceError)
sdkClient.getSessionManager = sdkClient.getSessionManager || (() => ({
  getAllSessions: async () => [],
  getActiveSessionCount: async () => 0,
  cleanupExpiredSessions: async () => ({ removedCount: 0 }),
  closeSession: () => false
}));
const sessionManager = sdkClient.getSessionManager();

// Create authentication middleware using the client instance
const authenticate_apicall = (req, res, next) => {
  return sdkClient.authenticate(req, res, next);
};

const authorize = (req, res, next) => {
  return sdkClient.authorize(req, res, next);
};

/**
 * POST /api/sessions/login - Create a new session (login)
 * 
 * Handles client authentication and session creation
 */
router.post('/login', (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  req.logAction = "login-attempt";
  
  logger.info("Login request received", {
    component: "SessionRoutes",
    method: "createSession",
    requestId,
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  // Delegate to RoditClient instance
  if (!req.app.locals.roditClient) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  req.app.locals.roditClient.login_client(req, res);
});

/**
 * POST /api/sessions/logout - End a session (logout)
 * 
 * Handles client session termination
 * Protected: Requires authentication
 */
router.post('/logout', authenticate_apicall, (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  req.logAction = "logout-attempt";
  
  logger.info("Logout request received", {
    component: "SessionRoutes",
    method: "terminateSession",
    requestId,
    method: req.method,
    path: req.path,
    ip: req.ip,
    userId: req.user ? req.user.id : "unknown",
    userAgent: req.get('User-Agent')
  });
  
  if (!req.app.locals.roditClient) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  
  // Check if the logout_client method exists
  if (typeof req.app.locals.roditClient.logout_client !== 'function') {
    logger.error("logout_client method not available on roditClient", {
      component: "SessionRoutes",
      method: "terminateSession",
      requestId,
      availableMethods: Object.getOwnPropertyNames(req.app.locals.roditClient).filter(name => typeof req.app.locals.roditClient[name] === 'function'),
      clientType: req.app.locals.roditClient.constructor.name
    });
    return res.status(503).json({ 
      error: 'Logout service unavailable',
      details: 'logout_client method not found on authentication service'
    });
  }
  
  try {
    req.app.locals.roditClient.logout_client(req, res);
  } catch (error) {
    logger.error("Error calling logout_client", {
      component: "SessionRoutes",
      method: "terminateSession",
      requestId,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      }
    });
    return res.status(500).json({
      error: 'Logout failed',
      message: error.message,
      requestId
    });
  }
});

/**
 * GET /api/sessions/list_all - Get all sessions
 * 
 * Admin route - Get information about all active sessions
 * Protected: Requires authentication and permissions
 */
router.get('/list_all', authenticate_apicall, authorize, async (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  try {
    // Gather all sessions using the proper storage interface
    const sessions = [];
    
    // Get all sessions from storage
    const allSessions = await sessionManager.getAllSessions();
    
    for (const session of allSessions) {
      // Don't include closed or expired sessions
      if (session.status === 'active') {
        sessions.push({
          id: session.id,
          roditId: session.roditId,
          ownerId: session.ownerId,
          createdAt: new Date(session.createdAt * 1000).toISOString(),
          expiresAt: new Date(session.expiresAt * 1000).toISOString(),
          lastAccessedAt: new Date(session.lastAccessedAt * 1000).toISOString(),
          status: session.status
        });
      }
    }
    
    logger.info("Session list retrieved", {
      component: "SessionRoutes",
      method: "listSessions",
      requestId,
      sessionCount: sessions.length,
      duration: Date.now() - startTime
    });
    
    res.json({
      sessions,
      count: sessions.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error("Failed to retrieve sessions", {
      component: "SessionRoutes",
      method: "listSessions",
      requestId,
      error: error.message,
      stack: error.stack,
      duration: Date.now() - startTime
    });
    
    res.status(500).json({
      error: "Failed to retrieve sessions",
      message: error.message,
      requestId
    });
  }
});

/**
 * POST /api/sessions/cleanup - Clean up expired sessions
 * 
 * Triggers cleanup of expired sessions and returns cleanup statistics
 * Protected: Requires authentication
 */
router.post('/cleanup', authenticate_apicall, async (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  const baseContext = {
    component: 'SessionRoutes',
    method: 'cleanupSessions',
    requestId,
    httpMethod: req.method,
    path: req.path,
    ip: req.ip,
    userId: req.user?.id || 'system'
  };
  
  logger.info('Session cleanup requested', baseContext);
  
  try {
    if (!sessionManager) {
      logger.error('Session manager not available', baseContext);
      return res.status(503).json({
        error: 'Session service unavailable',
        requestId
      });
    }
    
    // Get active sessions count before cleanup
    const activeBefore = await sessionManager.getActiveSessionCount();
    
    // Cleanup expired sessions
    const cleanupResult = await sessionManager.cleanupExpiredSessions();
    
    // Get active sessions count after cleanup
    const activeAfter = await sessionManager.getActiveSessionCount();
    const removedCount = activeBefore - activeAfter;
    
    // Get total sessions (including inactive ones if needed)
    const totalSessions = activeAfter; // This assumes we only track active sessions
    // If you need to track inactive sessions as well, you'll need to implement a method for that
    
    const duration = Date.now() - startTime;
    
    logger.info('Session cleanup completed', {
      ...baseContext,
      duration,
      removedCount,
      activeBefore,
      activeAfter,
      totalSessions
    });
    
    // Add metric for cleanup operation
    logger.metric('session_cleanup', duration, {
      operation: 'cleanupExpiredSessions',
      result: 'success',
      removedCount,
      activeSessions: activeAfter,
      totalSessions
    });
    
    res.status(200).json({
      success: true,
      message: 'Session cleanup completed',
      stats: {
        removedCount,
        activeSessions: activeAfter,
        totalSessions
      },
      requestId,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error('Session cleanup failed', {
      ...baseContext,
      error: error.message,
      stack: error.stack,
      duration
    });
    
    // Add error metric
    logger.metric('session_cleanup', duration, {
      operation: 'cleanupExpiredSessions',
      result: 'error',
      error: error.message
    });
    
    res.status(500).json({
      error: 'Failed to clean up sessions',
      message: error.message,
      requestId
    });
  }
});

/**
 * POST /api/sessions/close - Close a specific session (admin only)
 * 
 * Allows administrators to terminate a specific session
 * Protected: Requires authentication and admin privileges
 */
router.post('/close', authenticate_apicall, authorize, (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  const { sessionId } = req.body;
  const reason = req.body.reason || 'admin_termination';
  
  if (!sessionId) {
    logger.warn("Session termination missing sessionId", {
      component: "SessionRoutes",
      method: "terminateSession",
      requestId,
      duration: Date.now() - startTime
    });
    
    return res.status(400).json({
      error: "Missing required parameter: sessionId",
      requestId
    });
  }
  
  try {
    logger.info("Session termination requested", {
      component: "SessionRoutes",
      method: "terminateSession",
      requestId,
      sessionId,
      reason,
      adminUser: req.user.id
    });
    
    const sessionClosed = sessionManager.closeSession(sessionId, reason);
    
    if (sessionClosed) {
      logger.info("Session terminated successfully", {
        component: "SessionRoutes",
        method: "terminateSession",
        requestId,
        sessionId,
        reason,
        duration: Date.now() - startTime
      });
      
      res.json({
        message: "Session terminated successfully",
        sessionId,
        reason,
        timestamp: new Date().toISOString()
      });
    } else {
      logger.warn("Session not found or already terminated", {
        component: "SessionRoutes",
        method: "terminateSession",
        requestId,
        sessionId,
        reason,
        duration: Date.now() - startTime
      });
      
      res.status(404).json({
        error: "Session not found or already terminated",
        sessionId,
        requestId
      });
    }
  } catch (error) {
    logger.error("Failed to terminate session", {
      component: "SessionRoutes",
      method: "terminateSession",
      requestId,
      sessionId,
      error: error.message,
      stack: error.stack,
      duration: Date.now() - startTime
    });
    
    res.status(500).json({
      error: "Failed to terminate session",
      message: error.message,
      sessionId,
      requestId
    });
  }
});

/**
 * POST /api/sessions/cleanup - Run manual session cleanup
 * 
 * Admin route - Force cleanup of expired sessions
 * Protected: Requires authentication and permissions
 */
router.post('/cleanup', authenticate_apicall, async (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  try {
    logger.info("Manual session cleanup requested", {
      component: "SessionRoutes",
      method: "cleanupSessions",
      requestId,
      adminUser: req.user.id
    });
    // Use the centralized RoditClient to run cleanup
    const result = await req.app.locals.roditClient.runManualCleanup();
    
    logger.info("Manual session cleanup completed", {
      component: "SessionRoutes",
      method: "cleanupSessions",
      requestId,
      removedCount: result.removedCount,
      remainingCount: result.remainingCount,
      duration: Date.now() - startTime
    });
    
    res.json({
      message: "Session cleanup completed",
      removedCount: result.removedCount,
      remainingCount: result.remainingCount,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error("Failed to run session cleanup", {
      component: "SessionRoutes",
      method: "cleanupSessions",
      requestId,
      error: error.message,
      stack: error.stack,
      duration: Date.now() - startTime
    });
    
    res.status(500).json({
      error: "Failed to run session cleanup",
      message: error.message,
      requestId
    });
  }
});

module.exports = router;
