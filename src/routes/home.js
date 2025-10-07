// Importing express module
const express = require("express");
const router = express.Router();
const { ulid } = require("ulid");
const { RoditClient } = require("@rodit/rodit-auth-be");

// Create SDK client instance to access all functionality
const sdkClient = new RoditClient();
const logger = sdkClient.getLogger();
const { createLogContext, logErrorWithMetrics } = logger;

// Handling request using router
router.get("/home", (req, res, next) => {
  const requestId = req.requestId || ulid();
  const startTime = Date.now();
  
  const baseContext = createLogContext({
    requestId,
    component: 'HomeRoutes',
    method: 'getHomepage',
    endpoint: '/api/home',
    httpMethod: req.method,
    userId: req.user?.id,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    headers: Object.keys(req.headers),
    queryParams: Object.keys(req.query || {})
  });
  
  logger.debugWithContext("Processing homepage request", baseContext);
  
  try {
    // Send the homepage response
    res.send("This is the homepage request");
    
    const duration = Date.now() - startTime;
    logger.infoWithContext("Homepage request processed successfully", {
      ...baseContext,
      statusCode: 200,
      duration
    });
    
    // Add metric for successful operation
    logger.metric('route_operations', duration, {
      operation: 'getHomepage',
      result: 'success'
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logErrorWithMetrics(
      'Error processing homepage request',
      {
        ...baseContext,
        duration
      },
      error,
      'route_error',
      {
        operation: 'getHomepage',
        result: 'error',
        duration
      }
    );
    
    res.status(500).json({
      error: 'Failed to process homepage request',
      message: error.message,
      requestId
    });
  }
});

// Respond to HEAD requests for health/benchmark probes
router.head("/home", (req, res) => {
  // Minimal fast response for probes
  res.status(200).end();
});

// Importing the router
module.exports = router;