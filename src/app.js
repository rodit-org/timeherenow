// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// Time Here Now - API

const express = require("express");
const crypto = require("crypto");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("../api-docs/swagger.json");
const { ulid } = require("ulid");
const { RoditClient } = require("@rodit/rodit-auth-be");
const loginRoutes = require("./routes/login");
const logoutRoutes = require("./protected/logout");

// Simple logger for Time Here Now API
const logger = {
  info: (msg, meta) => console.log(`[INFO] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta || ''),
  debug: (msg, meta) => console.log(`[DEBUG] ${msg}`, meta || ''),
  warn: (msg, meta) => console.warn(`[WARN] ${msg}`, meta || '')
};

// Configuration constants
const SERVERPORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";
const SERVICE_NAME = "Time Here Now API";

// Express app setup
const app = express();

// Store server instance for graceful shutdown
let server;

// Configure Express to trust proxies for correct client IP detection
// Using a specific configuration instead of 'true' to prevent IP spoofing
app.set("trust proxy", 1);

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Basic logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp
  });
  next();
});

// Performance monitoring middleware
app.use((req, res, next) => {
  req.startTime = Date.now();
  req.requestId = req.headers['x-request-id'] || req.headers['x-correlation-id'] || ulid();
  req.traceId = req.headers['x-trace-id'] || crypto.randomUUID();
  
  // Add response tracking
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    logger.debug(`Request completed: ${req.method} ${req.path}`, {
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      requestId: req.requestId
    });
  });
  next();
});


// Swagger documentation setup
app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec)
);

// Setup routes
function setupRoutes() {
  // Health check endpoint
  app.get("/health", (req, res) => {
    res.status(200).json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      service: SERVICE_NAME
    });
  });

  // Public login route (unprotected)
  app.use("/api", loginRoutes);

  // Protect subsequent /api routes with authentication (authorization optional for now)
  if (app.locals.roditClient && typeof app.locals.roditClient.authenticate === 'function') {
    app.use("/api", app.locals.roditClient.authenticate);
  } else {
    logger.warn("Authentication middleware not available - /api routes are not protected");
  }

  // Time Here Now API routes (protected)
  const timezoneRoutes = require("./protected/timezone");
  app.use("/api", timezoneRoutes);

  // Logout route (already requires auth in its own router; also after global auth)
  const protectedLogoutRoutes = require("./protected/logout");
  app.use("/api", protectedLogoutRoutes);

  // Error handling middleware for routes
  app.use((err, req, res, next) => {
    const requestId = req.requestId || ulid();
    
    logger.error("Server error occurred", {
      message: err.message,
      method: req.method,
      url: req.originalUrl,
      userIP: req.ip,
      errorCode: err.code || "500",
      requestId: requestId,
      timestamp: new Date().toISOString(),
      stack: isProduction ? undefined : err.stack
    });
    
    res.status(500).json({ 
      error: "Internal Server Error",
      message: err.message,
      requestId: requestId,
      timestamp: new Date().toISOString()
    });
  });
}

// Server startup
async function startServer() {
  try {
    // Initialize authentication client and expose to routes
    try {
      const authClient = await RoditClient.create('server');
      app.locals.roditClient = authClient;
      logger.info("Authentication client initialized");
    } catch (authErr) {
      logger.warn("Failed to initialize authentication client", { error: authErr.message });
    }

    // Setup routes
    setupRoutes();

    // Expose raw Swagger JSON for tooling access
    app.get('/swagger.json', (req, res) => {
      res.json(swaggerSpec);
    });

    // Start the HTTP server
    server = app.listen(SERVERPORT, () => {
      const serverInfo = {
        port: SERVERPORT,
        env: process.env.NODE_ENV || "development",
        service: SERVICE_NAME,
        endpoints: [
          { method: 'PUT', path: '/api/timezone', description: 'List all timezones (JSON)' },
          { method: 'PUT', path: '/api/timezone.txt', description: 'List all timezones (Text)' },
          { method: 'PUT', path: '/api/timezone/area', description: 'List timezones for area' },
          { method: 'PUT', path: '/api/timezone/area.txt', description: 'List timezones for area (Text)' },
          { method: 'PUT', path: '/api/timezone/time', description: 'Get time for timezone' },
          { method: 'PUT', path: '/api/timezone/time.txt', description: 'Get time for timezone (Text)' },
          { method: 'PUT', path: '/api/ip', description: 'Get time based on IP' },
          { method: 'PUT', path: '/api/ip.txt', description: 'Get time based on IP (Text)' },
          { method: 'PUT', path: '/api/near-health', description: 'NEAR RPC health check' },
          { method: 'GET', path: '/health', description: 'Health check' },
          { method: 'GET', path: '/api-docs', description: 'API documentation' }
        ]
      };
      
      logger.info("Time Here Now API server started", serverInfo);
      
      // For development, show endpoints
      if (process.env.NODE_ENV !== 'production') {
        console.log(`\n🌍 Time Here Now API running on port ${SERVERPORT}`);
        console.log('📚 Available endpoints:');
        serverInfo.endpoints.forEach(endpoint => {
          console.log(`  ${endpoint.method.padEnd(4)} ${endpoint.path.padEnd(30)} - ${endpoint.description}`);
        });
        console.log(`\n📖 API Documentation: http://localhost:${SERVERPORT}/api-docs\n`);
      }
    });

    // Graceful shutdown handling
    const shutdown = (signal) => {
      logger.info("Shutting down gracefully", {
        signal: signal || "unknown",
        timestamp: new Date().toISOString()
      });
      
      if (server) {
        server.close(() => {
          logger.info("HTTP server closed");
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
      error: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
}

startServer();
