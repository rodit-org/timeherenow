// Copyright (c) 2024 Discernible, Inc. All rights reserved.

const express = require("express");
const crypto = require("crypto");
const { RoditClient, logger, loggingmw, config } = require("@rodit/rodit-auth-be");
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");
const { ulid } = require("ulid");

// Configuration constants
const SERVERPORT = config.get("SERVERPORT");
const isProduction = process.env.NODE_ENV === "production";
const SERVICE_NAME = config.get("SERVICE_NAME");

// Initialize rate limiter
// let ratelimiter = ratelimitmw(100, 15);

// Express app setup
const app = express();

// Store server instance for graceful shutdown
let server;
let roditClient; // Will be initialized in startServer()

// Configure Express to trust proxies for correct client IP detection
// Using a specific configuration instead of 'true' to prevent IP spoofing
app.set("trust proxy", 1);

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Apply logging middleware
app.use(loggingmw);

// Performance monitoring middleware
app.use((req, res, next) => {
  req.startTime = Date.now();
  req.requestId = req.headers['x-request-id'] || req.headers['x-correlation-id'] || ulid();
  req.traceId = req.headers['x-trace-id'] || crypto.randomUUID();
  
  // Add response tracking
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    req.duration = duration;
    
    // Use structured logging with context
    logger.debugWithContext("Request performance metrics", {
      component: "API",
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      requestId: req.requestId,
      traceId: req.traceId,
      userAgent: req.get('User-Agent'),
      referer: req.get('Referer'),
      contentLength: res.get('Content-Length'),
      contentType: res.get('Content-Type')
    });
    
    // Log metrics for monitoring systems
    logger.metric('request_duration_ms', duration, {
      method: req.method,
      path: req.path,
      status: res.statusCode
    });
  });
  next();
});

// Action logging middleware - tracks user actions
app.use((req, res, next) => {
  if (req.logAction) {
    logger.infoWithContext("Action executed", {
      component: "API",
      action: req.logAction,
      path: req.path,
      method: req.method,
      ip: req.ip,
      userId: req.user ? req.user.id : "anonymous",
      roditId: req.user ? req.user.roditId : null,
      requestId: req.requestId,
      traceId: req.traceId,
      timestamp: new Date().toISOString(),
      service: req.logService || SERVICE_NAME,
      resource: req.resource || req.path
    });
  }
  next();
});

// Swagger documentation setup
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "RODIT Signing API",
      version: "1.0.0",
      description: `API service for signing server and client RODIT IDs using a secure vault-stored Key Pair (${
        isProduction ? "Production" : "Development"
      } Environment)`,
      contact: {
        name: "API Support",
        url: "https://timeherenow.rodit.org/support",
        email: "support@rodit.org",
      },
    },
    components: {
      securitySchemes: {
        auth: {
          type: "apiKey",
          in: "header",
          name: "X-RODIT-Token",
          description: "RODiT mutual authentication token",
        },
      },
    },
    security: [{ auth: [] }],
    tags: [
      {
        name: "Server RODIT",
        description: "Operations related to server RODIT signing",
      },
      {
        name: "Client RODIT",
        description: "Operations related to client RODIT signing",
      },
    ],
    paths: {
      "/api/root/signroot": {
        post: {
          tags: ["Portal/Sanctum RODIT"],
          summary: "Sign Portal/Sanctum RODIT",
          description:
            "Sign a Portal/Sanctum RODIT ID using the secure vault-stored Key Pair",
        },
      },
      "/api/timeherenow/timeherenow": {
        post: {
          tags: ["Client RODIT"],
          summary: "Sign client RODIT",
          description:
            "Sign a client RODIT ID using the secure vault-stored Key Pair",
        },
      },
    },
  },
  apis: ["./app.js", "./protected/*.js"],
};

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerJsdoc(swaggerOptions))
);

// Function to setup routes that depend on roditClient
function setupRoutes() {
  // Health check endpoint
  app.get("/health", (req, res) => {
    res.status(200).json({
      status: "healthy",
      timestamp: new Date().toISOString(),
    });
  });
  
  // Login endpoint - accepts RODiT credentials and returns JWT token
  app.post("/api/login", (req, res, next) => {
    req.logAction = "login-attempt";
    req.logService = "authentication";
    req.requestId = req.headers['x-request-id'] || req.headers['x-correlation-id'] || ulid();
    req.traceId = req.headers['x-trace-id'] || crypto.randomUUID();
    
    logger.infoWithContext("Login request received", {
      component: "API",
      method: "login",
      requestId: req.requestId,
      traceId: req.traceId,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      service: "authentication"
    });
    next();
  },
  // Use the SDK's login handler that processes RODiT credentials
  async (req, res) => {
    try {
      // Delegate to the SDK's login_client function which handles RODiT authentication
      await roditClient.login_client(req, res);
    } catch (error) {
      logger.errorWithContext("Login processing failed", {
        component: "API",
        method: "login",
        requestId: req.requestId,
        traceId: req.traceId,
        error: error.message,
        timestamp: new Date().toISOString()
      });
      
      res.status(500).json({
        error: "Login processing failed",
        requestId: req.requestId,
        timestamp: new Date().toISOString()
      });
    }
  });

  /**
   * Logout endpoint
   */
  app.post('/api/logout', roditClient.authenticate, (req, res) => {
  req.logAction = "logout-attempt";
  req.logService = "authentication";
  
  logger.infoWithContext("Logout request received", {
    component: "API",
    method: "logout",
    requestId: req.requestId,
    traceId: req.traceId,
    path: req.path,
    ip: req.ip,
    userId: req.user ? req.user.id : "anonymous",
    roditId: req.user ? req.user.roditId : null,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString(),
    service: "authentication"
  });
  
  roditClient.logoutClient(req, res);
  });

  // Protected routes
  const timeherenowprotectedRoute = require("./protected/timeherenow");
  const signrootprotectedRoute = require("./protected/signroot");

  // Use the SDK's authenticate middleware for protected routes
  // Add permission validation if needed for specific routes
  app.use("/api/timeherenow", roditClient.authenticate, timeherenowprotectedRoute);
  app.use("/api/root", signrootprotectedRoute);

  // Error handling middleware for routes
  app.use((err, req, res, next) => {
    const requestId = req.requestId || ulid();
    const traceId = req.traceId || crypto.randomUUID();
    
    logger.errorWithContext(
      "Server error occurred",
      {
        component: "API",
        message: err.message,
        method: req.method,
        url: req.originalUrl,
        userIP: req.ip,
        userId: req.user ? req.user.id : "anonymous",
        roditId: req.user ? req.user.roditId : null,
        errorCode: err.code || "936",
        route: req.route ? req.route.path : "unknown",
        requestId: requestId,
        traceId: traceId,
        timestamp: new Date().toISOString(),
        service: req.logService || SERVICE_NAME,
        action: req.logAction || "unspecified",
        statusCode: err.statusCode || 500,
        stack: isProduction ? undefined : err.stack
      },
      err // Pass the error object directly
    );
    
    res.status(500).json({ 
      error: "Error 936: Internal Server Error",
      requestId: req.requestId || ulid(),
      timestamp: new Date().toISOString()
    });
  });
} // End of setupRoutes function

// Server startup
async function startServer() {
  try {
    // Initialize the RODiT SDK and create RoditClient
    roditClient = await RoditClient.create('timeherenow');

    // Store roditClient in app.locals for access by route modules
    app.locals.roditClient = roditClient;

    logger.info("RODiT configuration initialized", {
      component: "vault",
      status: "initialized"
    });
    
    // Setup routes that depend on roditClient
    setupRoutes();

    // Start the HTTP server
    server = app.listen(SERVERPORT, () => {
      const serverInfo = {
        port: SERVERPORT,
        env: process.env.NODE_ENV || "development",
        endpoints: [
          { method: 'POST', path: '/api/login', description: 'Login with RODiT credentials' },
          { method: 'POST', path: '/api/logout', description: 'Logout and invalidate session' },
          { method: 'POST', path: '/api/timeherenow', description: 'Portal signing operations' },
          { method: 'POST', path: '/api/root', description: 'Root signing operations' },
          { method: 'GET', path: '/api-docs', description: 'Swagger API documentation' }
        ]
      };
      
      logger.info("Server started", serverInfo);
      
      // For development, still log to console but through the logger
      if (process.env.NODE_ENV !== 'production') {
        logger.debug(`\nRODiT Signing Portal running on port ${SERVERPORT}`, { component: 'ServerStartup' });
        logger.debug('Available endpoints:', { component: 'ServerStartup' });
        serverInfo.endpoints.forEach(endpoint => {
          logger.debug(`  ${endpoint.method} ${endpoint.path} - ${endpoint.description}`, 
            { component: 'ServerStartup' });
        });
      }
    });

    // Graceful shutdown handling
    const shutdown = async (signal) => {
      logger.info("Shutting down gracefully", {
        component: "AppLifecycle",
        signal: signal || "unknown",
        time: new Date().toISOString()
      });
      
      if (server) {
        server.close(() => {
          logger.info("HTTP server closed", { component: "http-server" });
          process.exit(0);
        });
      } else {
        process.exit(0);
      }
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (error) {
    logger.error("Server initialization failed", {
      component: "AppLifecycle",
      errorCode: "907",
      error: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
}

startServer();
