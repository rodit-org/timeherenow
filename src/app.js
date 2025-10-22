// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// Time Here Now - API

const config = require("config");
const express = require("express");
const crypto = require("crypto");
const winston = require("winston");
const LokiTransport = require("winston-loki");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("../api-docs/swagger.json");
const { ulid } = require("ulid");
const { RoditClient, logger } = require("@rodit/rodit-auth-be");
const loginRoutes = require("./routes/login");
const logoutRoutes = require("./protected/logout");

// Configure winston-loki logger following SDK README guidelines
(() => {
  try {
    console.log("=== Configuring winston-loki for Time Here Now API ===");
    const lokiUrl = process.env.LOKI_URL;
    const logLevel = process.env.LOG_LEVEL || 'info';
    const skipTls = String(process.env.LOKI_TLS_SKIP_VERIFY || "").toLowerCase() === "true";
    const basicAuth = process.env.LOKI_BASIC_AUTH;

    console.log("Environment variables:");
    console.log("  LOKI_URL:", lokiUrl || "NOT SET");
    console.log("  LOKI_TLS_SKIP_VERIFY:", process.env.LOKI_TLS_SKIP_VERIFY || "NOT SET");
    console.log("  LOKI_BASIC_AUTH:", basicAuth ? "SET" : "NOT SET");
    console.log("  LOG_LEVEL:", logLevel);

    const transports = [
      new winston.transports.Console({ format: winston.format.json(), level: logLevel })
    ];

    if (lokiUrl) {
      console.log("Creating winston-loki transport...");
      const serviceLabel = process.env.SERVICE_NAME || "timeherenow-api";
      const lokiOptions = {
        host: lokiUrl,
        labels: { app: serviceLabel, service_name: serviceLabel, component: "rodit-sdk" },
        json: true,
        level: logLevel,
        batching: true,
        gracefulShutdown: true,
        replaceTimestamp: true,
        timeout: 5000,
      };

      if (basicAuth) {
        lokiOptions.basicAuth = basicAuth;
        console.log("Added basic auth to Loki options");
      }
      if (skipTls) {
        lokiOptions.ssl = { rejectUnauthorized: false };
        console.log("Added TLS skip verification to Loki options");
      }

      console.log("Loki transport options:", JSON.stringify(lokiOptions, null, 2));
      const lokiTransport = new LokiTransport(lokiOptions);
      
      lokiTransport.on('error', (err) => {
        console.error("❌ winston-loki transport ERROR:", err.message);
        console.error("Error details:", err);
      });

      lokiTransport.on('warn', (warn) => {
        console.warn("⚠️ winston-loki transport WARN:", warn);
      });

      transports.push(lokiTransport);
      console.log("✅ winston-loki transport added to transports");
    } else {
      console.log("❌ LOKI_URL not set - winston-loki transport will not be created");
    }

    const customLogger = winston.createLogger({
      level: logLevel,
      format: winston.format.json(),
      transports,
    });

    console.log("Created custom logger with", transports.length, "transports");
    logger.setLogger(customLogger);
    console.log("✅ Custom logger injected into SDK");
    
    // Test the logger immediately
    customLogger.info("winston-loki transport test log", { 
      timestamp: new Date().toISOString(),
      test: true,
      component: "winston-loki-setup"
    });
    console.log("✅ Test log sent through custom logger");
    
  } catch (e) {
    console.warn("❌ SDK Loki logger injection failed:", e?.message || e);
    console.error("Full error:", e);
  }
})();

// Configuration constants
const SERVERPORT = config.get('SERVERPORT', process.env.PORT || 8080);
const isProduction = process.env.NODE_ENV === "production";
const SERVICE_NAME = process.env.SERVICE_NAME || "Time Here Now API";

const RATE_LIMIT_SETTINGS = {
  global: { max: 240, windowMinutes: 1 },
  login: { max: 20, windowMinutes: 1 },
  signclient: { max: 6, windowMinutes: 1 }
};

// Express app setup
const app = express();
app.disable("x-powered-by");
const TimeZoneService = require('./lib/timezone-service');
// Dedicated service instance for health reporting (NEAR status)
const tzHealthService = new TimeZoneService();

// Store server instance for graceful shutdown
let server;
let rateLimitersApplied = false;

function applyRateLimitersIfAvailable() {
  if (rateLimitersApplied) {
    return;
  }

  const sdkFactory = app.locals?.roditClient?.getRateLimitMiddleware?.();
  const { global, login, signclient } = RATE_LIMIT_SETTINGS;

  if (typeof sdkFactory !== "function") {
    logger.warn("Rate limiting middleware not available from SDK - skipping rate limiter setup");
    return;
  }

  app.use('/api/login', sdkFactory(login.max, login.windowMinutes));
  app.use('/api/signclient', sdkFactory(signclient.max, signclient.windowMinutes));
  app.use('/api', sdkFactory(global.max, global.windowMinutes));

  rateLimitersApplied = true;

  logger.info("Rate limiting middleware applied", {
    component: "TimeHereNowAPI",
    global,
    login,
    signclient
  });
}

// Configure Express to trust proxies for correct client IP detection
// Using a specific configuration instead of 'true' to prevent IP spoofing
app.set("trust proxy", 1);

// Parse JSON and URL-encoded bodies with explicit limits
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

// Request context middleware (must be before SDK logging middleware)
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || req.headers['x-correlation-id'] || ulid();
  req.traceId = req.headers['x-trace-id'] || crypto.randomUUID();
  req.startTime = Date.now();
  next();
});

// Performance monitoring middleware
app.use((req, res, next) => {
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    logger.debugWithContext('Request completed', {
      component: 'API',
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      requestId: req.requestId,
      userAgent: req.get('User-Agent')
    });
    logger.metric('request_duration_ms', duration, {
      method: req.method,
      path: req.path,
      status: res.statusCode
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
  app.get("/health", async (req, res) => {
    try {
      const near = await tzHealthService.healthCheck();
      res.status(200).json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        service: SERVICE_NAME,
        near
      });
    } catch (e) {
      // On failure, still report basic health with NEAR status degraded
      res.status(200).json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        service: SERVICE_NAME,
        near: { status: 'unhealthy', error: e.message, timestamp: new Date().toISOString() }
      });
    }
  });

  // Public login route (unprotected)
  app.use("/api", loginRoutes);

  // Public signclient route (unprotected) with its own CORS in router
  const signclientRoutes = require("./routes/signclient");
  app.use("/api", signclientRoutes);

  // Protect subsequent /api routes with authentication (authorization optional for now)
  if (app.locals.roditClient && typeof app.locals.roditClient.authenticate === 'function') {
    app.use("/api", app.locals.roditClient.authenticate);
  } else {
    logger.warn("Authentication middleware not available - /api routes are not protected", {
      component: 'TimeHereNowAPI'
    });
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
    
    logger.errorWithContext("Server error occurred", {
      component: 'API',
      message: err.message,
      method: req.method,
      url: req.originalUrl,
      userIP: req.ip,
      userId: req.user ? req.user.id : 'anonymous',
      statusCode: err.statusCode || 500,
      requestId: requestId
    }, err);
    
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
      
      // Apply SDK logging middleware
      const loggingMiddleware = authClient.getLoggingMiddleware();
      app.use(loggingMiddleware);
      
      logger.info("Authentication client initialized", {
        component: 'TimeHereNowAPI',
        service: SERVICE_NAME
      });
      applyRateLimitersIfAvailable();
    } catch (authErr) {
      logger.warn("Failed to initialize authentication client", { 
        component: 'TimeHereNowAPI',
        error: authErr.message 
      });
    }

    // Ensure rate limiters are applied even if SDK init failed
    applyRateLimitersIfAvailable();

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
          { method: 'POST', path: '/api/login', description: 'Authentication' },
          { method: 'POST', path: '/api/logout', description: 'Logout' },
          { method: 'POST', path: '/api/signclient', description: 'Sign client RODiT token' },
          { method: 'PUT', path: '/api/timezone', description: 'List all timezones' },
          { method: 'PUT', path: '/api/timezone/area', description: 'List timezones for area' },
          { method: 'PUT', path: '/api/timezone/time', description: 'Get time for timezone' },
          { method: 'PUT', path: '/api/timezones/by-country', description: 'List timezones by country code' },
          { method: 'PUT', path: '/api/ip', description: 'Get time based on IP' },
          { method: 'PUT', path: '/api/sign/hash', description: 'Sign hash with NEAR timestamp' },
          { method: 'GET', path: '/health', description: 'Health check' },
          { method: 'GET', path: '/api-docs', description: 'API documentation' }
        ]
      };
      
      logger.info("Time Here Now API server started", {
        component: 'TimeHereNowAPI',
        ...serverInfo
      });

      if (server) {
        server.keepAliveTimeout = 5000;
        server.headersTimeout = 35000;
        server.requestTimeout = 30000;
        server.maxRequestsPerSocket = 100;
        logger.info("HTTP server timeouts configured", {
          component: 'TimeHereNowAPI',
          keepAliveTimeoutMs: server.keepAliveTimeout,
          headersTimeoutMs: server.headersTimeout,
          requestTimeoutMs: server.requestTimeout,
          maxRequestsPerSocket: server.maxRequestsPerSocket
        });
      }

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
        component: 'AppLifecycle',
        signal: signal || "unknown",
        time: new Date().toISOString()
      });
      
      if (server) {
        server.close(() => {
          logger.info("HTTP server closed", {
            component: 'AppLifecycle'
          });
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
      component: 'TimeHereNowAPI',
      error: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
}

startServer();
