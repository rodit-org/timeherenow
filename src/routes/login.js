const express = require("express");
const router = express.Router();
const { ulid } = require("ulid");

// Import logger utilities from SDK
const { logger } = require('@rodit/rodit-auth-be');
const { createLogContext, logErrorWithMetrics } = logger;

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
    path: req.path,
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

module.exports = router;