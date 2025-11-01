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
const authRoutes = require("./routes/auth.routes");
const { createUserRateLimitMiddleware } = require("./middleware/user-rate-limit");

// Configure winston-loki logger following SDK README guidelines
(() => {
  try {
    console.log("=== Configuring winston-loki for Time Here Now API ===");
    const lokiUrl = config.has('LOKI_URL') ? config.get('LOKI_URL') : null;
    const logLevel = config.get('LOG_LEVEL');
    const skipTls = config.has('LOKI_TLS_SKIP_VERIFY') ? String(config.get('LOKI_TLS_SKIP_VERIFY')).toLowerCase() === "true" : false;
    const basicAuth = config.has('LOKI_BASIC_AUTH') ? config.get('LOKI_BASIC_AUTH') : null;

    console.log("Configuration values:");
    console.log("  LOKI_URL:", lokiUrl || "NOT SET");
    console.log("  LOKI_TLS_SKIP_VERIFY:", skipTls ? "true" : "false");
    console.log("  LOKI_BASIC_AUTH:", basicAuth ? "SET" : "NOT SET");
    console.log("  LOG_LEVEL:", logLevel);

    const transports = [
      new winston.transports.Console({ format: winston.format.json(), level: logLevel })
    ];

    if (lokiUrl) {
      console.log("Creating winston-loki transport...");
      const serviceLabel = config.get('SERVICE_NAME');
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
const SERVERPORT = config.get('SERVERPORT');
const LOG_LEVEL = config.get('LOG_LEVEL', 'info');
const isProduction = ['info', 'warn', 'error'].includes(LOG_LEVEL);
const SERVICE_NAME = config.get('SERVICE_NAME');

const RATE_LIMIT_SETTINGS = config.has('RATE_LIMITING') 
  ? config.get('RATE_LIMITING')
  : {
      enabled: true, // Default to enabled if not configured
      login: { max: 20, windowMinutes: 1 },
      signclient: { max: 6, windowMinutes: 1 }
    };

// Express app setup
const app = express();
app.disable("x-powered-by");
const TimeZoneService = require('./services/timezone.service');
// Dedicated service instance for health reporting (NEAR status)
const tzHealthService = new TimeZoneService();

// Store server instance for graceful shutdown
let server;
let rateLimitersApplied = false;

function applyRateLimitersIfAvailable() {
  if (rateLimitersApplied) {
    return;
  }

  if (!RATE_LIMIT_SETTINGS.enabled) {
    logger.warn("Rate limiting is DISABLED via config (RATE_LIMITING.enabled = false)", {
      component: "TimeHereNowAPI",
      config: "config/default.json"
    });
    rateLimitersApplied = true; // Mark as applied to prevent retry
    return;
  }

  const sdkFactory = app.locals?.roditClient?.getRateLimitMiddleware?.();
  const { login, signclient } = RATE_LIMIT_SETTINGS;

  if (typeof sdkFactory !== "function") {
    logger.warn("Rate limiting middleware not available from SDK - skipping rate limiter setup");
    return;
  }

  // Apply IP-based rate limiting for unauthenticated endpoints
  app.use('/api/login', sdkFactory(login.max, login.windowMinutes));
  app.use('/api/signclient', sdkFactory(signclient.max, signclient.windowMinutes));

  rateLimitersApplied = true;

  logger.info("IP-based rate limiting applied for unauthenticated endpoints", {
    component: "TimeHereNowAPI",
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
      path: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      requestId: req.requestId,
      userAgent: req.get('User-Agent')
    });
    logger.metric('request_duration_ms', duration, {
      method: req.method,
      path: req.originalUrl,
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
      const response = {
        status: "healthy",
        timestamp: new Date().toISOString(),
        service: SERVICE_NAME,
        near
      };
      
      logger.debugWithContext("Health check successful", {
        component: 'API',
        nearStatus: near?.status,
        cacheAvailable: near?.cache_available
      });
      
      res.status(200).json(response);
    } catch (e) {
      // On failure, still report basic health with NEAR status degraded
      const response = {
        status: "healthy",
        timestamp: new Date().toISOString(),
        service: SERVICE_NAME,
        near: { status: 'unhealthy', error: e.message, timestamp: new Date().toISOString() }
      };
      
      logger.warnWithContext("Health check NEAR error", {
        component: 'API',
        error: e.message
      });
      
      res.status(200).json(response);
    }
  });

  // Authentication routes (login, logout, signclient)
  app.use("/api", authRoutes);
  
  // Public signclient route (unprotected) with its own CORS in router
  const signclientRoutes = require("./routes/signclient.routes");
  app.use("/api", signclientRoutes);

  // MCP (Model Context Protocol) routes - handles its own authentication per endpoint
  const mcpRoutes = require("./routes/mcp.routes");
  app.use("/api/mcp", mcpRoutes);

  // Protect subsequent /api routes with authentication (authorization optional for now)
  if (app.locals.roditClient && typeof app.locals.roditClient.authenticate === 'function') {
    app.use("/api", app.locals.roditClient.authenticate);
  } else {
    logger.warn("Authentication middleware not available - /api routes are not protected", {
      component: 'TimeHereNowAPI'
    });
  }

  // Apply user-based rate limiting for authenticated routes
  if (RATE_LIMIT_SETTINGS.enabled && app.locals.roditClient) {
    const userRateLimiter = createUserRateLimitMiddleware(app.locals.roditClient);
    app.use("/api", userRateLimiter);
    
    logger.info("User-based rate limiting applied for authenticated endpoints", {
      component: "TimeHereNowAPI"
    });
  } else if (!RATE_LIMIT_SETTINGS.enabled) {
    logger.warn("User-based rate limiting DISABLED via config (RATE_LIMITING.enabled = false)", {
      component: "TimeHereNowAPI",
      config: "config/default.json"
    });
  }

  // Feature-based routes (all protected after authentication middleware)
  const timezoneRoutes = require("./routes/timezone.routes");
  app.use("/api", timezoneRoutes);
  
  const timerRoutes = require("./routes/timer.routes");
  app.use("/api", timerRoutes);
  
  // Metrics routes (protected)
  const metricsRoutes = require("./routes/metrics.routes");
  app.use("/api/metrics", metricsRoutes);
  
  // Session management routes (protected)
  const sessionRoutes = require("./routes/session.routes");
  app.use("/api/sessions", sessionRoutes);

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
    // Wait for NEAR cache to initialize before accepting requests
    logger.info("Waiting for NEAR blockchain cache to initialize...", {
      component: 'TimeHereNowAPI'
    });
    try {
      await tzHealthService.waitForNearCache(10000);
      logger.info("NEAR cache initialized successfully", {
        component: 'TimeHereNowAPI'
      });
    } catch (cacheErr) {
      logger.warn("NEAR cache initialization timeout - server will start but time endpoints may return 503", {
        component: 'TimeHereNowAPI',
        error: cacheErr.message
      });
    }

    // Initialize authentication client and expose to routes
    try {
      const authClient = await RoditClient.create('server');
      app.locals.roditClient = authClient;
      
      // Apply SDK logging middleware BEFORE routes
      const loggingMiddleware = authClient.getLoggingMiddleware();
      app.use(loggingMiddleware);
      
      // Apply performance tracking middleware to track request counts BEFORE routes
      const performanceService = authClient.getPerformanceService();
      if (performanceService && typeof performanceService.recordRequest === 'function') {
        // Store performance service instance for debugging
        app.locals.performanceService = performanceService;
        
        // Create middleware to track all requests using recordRequest
        app.use((req, res, next) => {
          const startTime = Date.now();
          
          // Call recordRequest to increment request counter - pass req object
          performanceService.recordRequest(req);
          
          res.on('finish', () => {
            const duration = Date.now() - startTime;
            // Record error if status code indicates failure
            if (res.statusCode >= 400 && typeof performanceService.recordMetric === 'function') {
              performanceService.recordMetric('error_count', 1);
            }
            // Record request duration
            if (typeof performanceService.recordMetric === 'function') {
              performanceService.recordMetric('request_duration', duration);
            }
          });
          next();
        });
        logger.info("Performance tracking middleware applied using recordRequest", {
          component: 'TimeHereNowAPI',
          performanceServiceId: performanceService.constructor.name
        });
      } else {
        logger.warn("Performance tracking not available from SDK", {
          component: 'TimeHereNowAPI',
          hasPerformanceService: !!performanceService,
          performanceServiceType: performanceService?.constructor?.name,
          availableMethods: performanceService ? Object.getOwnPropertyNames(Object.getPrototypeOf(performanceService)) : []
        });
      }
      
      logger.info("Authentication client initialized", {
        component: 'TimeHereNowAPI',
        service: SERVICE_NAME
      });
      applyRateLimitersIfAvailable();
      
      // Setup routes AFTER middleware is applied
      setupRoutes();
    } catch (authErr) {
      logger.warn("Failed to initialize authentication client", { 
        component: 'TimeHereNowAPI',
        error: authErr.message 
      });
      // Setup routes even if auth client fails
      setupRoutes();
    }

    // Ensure rate limiters are applied even if SDK init failed
    applyRateLimitersIfAvailable();

    // Initialize timer persistence (restore timers and start auto-save)
    try {
      const timerModule = require("./routes/timer.routes");
      await timerModule.initializeTimerPersistence(app);
      logger.info("Timer persistence initialized", {
        component: 'TimeHereNowAPI'
      });
    } catch (timerErr) {
      logger.warn("Failed to initialize timer persistence", {
        component: 'TimeHereNowAPI',
        error: timerErr.message
      });
    }

    // Expose raw Swagger JSON for tooling access
    app.get('/swagger.json', (req, res) => {
      res.json(swaggerSpec);
    });

    // Start the HTTP server
    server = app.listen(SERVERPORT, () => {
      const serverInfo = {
        port: SERVERPORT,
        logLevel: LOG_LEVEL,
        service: SERVICE_NAME,
        endpoints: [
          { method: 'POST', path: '/api/login', description: 'Authentication' },
          { method: 'POST', path: '/api/logout', description: 'Logout' },
          { method: 'POST', path: '/api/signclient', description: 'Sign client RODiT token' },
          { method: 'POST', path: '/api/timezone', description: 'List all timezones' },
          { method: 'POST', path: '/api/timezone/area', description: 'List timezones for area' },
          { method: 'POST', path: '/api/timezone/time', description: 'Get time for timezone' },
          { method: 'POST', path: '/api/timezones/by-country', description: 'List timezones by country code' },
          { method: 'POST', path: '/api/ip', description: 'Get time based on IP' },
          { method: 'POST', path: '/api/sign/hash', description: 'Sign hash with NEAR timestamp' },
          { method: 'POST', path: '/api/timers/schedule', description: 'Schedule webhook timer' },
          { method: 'GET', path: '/api/mcp/resources', description: 'List MCP resources' },
          { method: 'GET', path: '/api/mcp/resource/:uri', description: 'Get MCP resource' },
          { method: 'GET', path: '/api/mcp/schema', description: 'Get MCP schema' },
          { method: 'GET', path: '/api/metrics', description: 'Get performance metrics' },
          { method: 'GET', path: '/api/metrics/system', description: 'Get system metrics' },
          { method: 'GET', path: '/api/sessions/list_all', description: 'List all sessions (admin)' },
          { method: 'POST', path: '/api/sessions/revoke', description: 'Revoke session (admin)' },
          { method: 'POST', path: '/api/sessions/cleanup', description: 'Cleanup expired sessions' },
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

      // For development (debug/trace), show endpoints
      if (!isProduction) {
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
