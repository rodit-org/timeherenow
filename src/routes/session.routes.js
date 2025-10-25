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
const { logger } = require('@rodit/rodit-auth-be');

// Authentication middleware - uses app.locals.roditClient
const authenticate_apicall = (req, res, next) => {
  const client = req.app?.locals?.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authenticate(req, res, next);
};

const authorize = (req, res, next) => {
  const client = req.app?.locals?.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authorization service unavailable' });
  }
  return client.authorize(req, res, next);
};

// Helper to get session manager from app.locals.roditClient
const getSessionManager = (req) => {
  const client = req.app?.locals?.roditClient;
  if (!client) {
    throw new Error('RoditClient not available');
  }
  return client.getSessionManager();
};

/**
 * NOTE: Login and logout are handled by /api/login and /api/logout routes.
 * This file only contains session management endpoints (list, revoke, cleanup).
 */

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
    
    // Get session manager from app.locals.roditClient
    const sessionManager = getSessionManager(req);
    
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
 * Protected: Requires authentication and authorization
 */
router.post('/cleanup', authenticate_apicall, authorize, async (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  const baseContext = {
    component: 'SessionRoutes',
    method: 'cleanupSessions',
    requestId,
    httpMethod: req.method,
    path: req.originalUrl,
    ip: req.ip,
    userId: req.user?.id || 'system'
  };
  
  logger.info('Session cleanup requested', baseContext);
  
  try {
    // Get session manager from app.locals.roditClient
    const sessionManager = getSessionManager(req);
    
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
 * POST /api/sessions/revoke - Revoke a specific session (admin only)
 * 
 * Allows administrators to terminate a specific session
 * Protected: Requires authentication and route permission
 * 
 * NOTE: Unlike /logout which requires the user to own the session,
 * /revoke only requires the route to be in the user's permissioned_routes.
 * This allows admins to revoke ANY session if they have permission to this endpoint.
 */
router.post('/revoke', authenticate_apicall, authorize, (req, res) => {
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
    
    // Get session manager from app.locals.roditClient
    const sessionManager = getSessionManager(req);
    
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

module.exports = router;
