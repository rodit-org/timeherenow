const express = require("express");
const router = express.Router();
const { ulid } = require("ulid");

// Import logger utilities from SDK
const { logger } = require('@rodit/rodit-auth-be');

// Authentication middleware - uses app.locals.roditClient
const authenticate = (req, res, next) => {
  const client = req.app?.locals?.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authenticate(req, res, next);
};

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: User login
 *     description: Authenticate using RODiT credentials
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - roditid
 *               - roditid_base64url_signature
 *             properties:
 *               roditid:
 *                 type: string
 *                 description: RODiT ID
 *               timestamp:
 *                 type: integer
 *                 description: Current timestamp (optional)
 *               roditid_base64url_signature:
 *                 type: string
 *                 description: Base64URL signature
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Authentication failed
 */
router.post('/login', async (req, res) => {
  req.logAction = "login-attempt";
  logger.info("Login request received", {
    component: "API",
    method: "login",
    requestId: req.requestId || ulid(),
    path: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  // Use the shared RoditClient stored in app.locals
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  
  // Ensure headers exist to prevent SDK errors
  if (!req.headers) {
    req.headers = {};
  }
  
  // Ensure user-agent header exists
  if (!req.headers['user-agent']) {
    req.headers['user-agent'] = req.get('User-Agent') || 'Unknown';
  }
  
  // Use the login_client method that handles Express req/res for client authentication
  await client.login_client(req, res);
});

/**
 * POST /api/logout
 * Logout endpoint - terminates the current session
 * Protected: Requires authentication
 */
router.post('/logout', authenticate, async (req, res) => {
  req.logAction = "logout-attempt";
  logger.info("Logout request received", {
    component: "AuthRoutes",
    method: "logout",
    requestId: req.requestId || ulid(),
    path: req.originalUrl,
    ip: req.ip,
    userId: req.user?.id,
    userAgent: req.get('User-Agent')
  });
  
  // Use the shared RoditClient stored in app.locals
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  
  // Check if the logout_client method exists
  if (typeof client.logout_client !== 'function') {
    logger.error("logout_client method not available on roditClient", {
      component: "AuthRoutes",
      method: "logout",
      requestId: req.requestId || ulid()
    });
    return res.status(503).json({ 
      error: 'Logout service unavailable',
      details: 'logout_client method not found on authentication service'
    });
  }
  
  try {
    await client.logout_client(req, res);
  } catch (error) {
    logger.error("Error calling logout_client", {
      component: "AuthRoutes",
      method: "logout",
      requestId: req.requestId || ulid(),
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      }
    });
    return res.status(500).json({
      error: 'Logout failed',
      message: error.message,
      requestId: req.requestId || ulid()
    });
  }
});

module.exports = router;