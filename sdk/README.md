# RODiT Authentication SDK

A comprehensive Node.js SDK for implementing RODiT-based mutual authentication, authorization, self-configuration, and session management in Express.js applications.

**Version:** 2.9.0  
**License:** Proprietary  
**Author:** Discernible Inc.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Installation & Setup](#installation--setup)
- [Authentication](#authentication)
- [Authorization & Permissions](#authorization--permissions)
- [Session Management](#session-management)
- [Configuration](#configuration)
- [Logging & Monitoring](#logging--monitoring)
- [Performance Tracking](#performance-tracking)
- [Webhooks](#webhooks)
- [Advanced Usage](#advanced-usage)
- [API Reference](#api-reference)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Installation

```bash
npm install @rodit/rodit-auth-be
```

### Basic Server Setup

```javascript
const express = require('express');
const { RoditClient, setExpressSessionStore } = require('@rodit/rodit-auth-be');
const { ulid } = require('ulid');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
let roditClient;

// Configure session storage BEFORE initializing RoditClient
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: './data',
  table: 'sessions'
});
setExpressSessionStore(sessionStore);

// Configure Express middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Request context middleware
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || ulid();
  req.startTime = Date.now();
  next();
});

// Server startup with SDK initialization
async function startServer() {
  try {
    // Initialize RODiT client (use 'server' for server applications)
    roditClient = await RoditClient.create('server');
    
    // Store client in app.locals for route access
    app.locals.roditClient = roditClient;
    
    // Get logger and other services from client
    const logger = roditClient.getLogger();
    const config = roditClient.getConfig();
    const loggingmw = roditClient.getLoggingMiddleware();
    
    // Apply logging middleware
    app.use(loggingmw);
    
    // Create authentication middleware
    const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
    const authorize = (req, res, next) => roditClient.authorize(req, res, next);
    
    // Public routes
    app.post('/api/login', (req, res) => {
      req.logAction = 'login-attempt';
      return roditClient.login_client(req, res);
    });
    
    // Protected routes
    app.post('/api/logout', authenticate, (req, res) => {
      req.logAction = 'logout-attempt';
      return roditClient.logout_client(req, res);
    });
    
    app.get('/api/protected', authenticate, (req, res) => {
      res.json({ message: 'Protected data', user: req.user });
    });
    
    // Protected + authorized routes
    app.use('/api/admin', authenticate, authorize, adminRoutes);
    
    const port = config.get('SERVERPORT', 3000);
    app.listen(port, () => {
      logger.info(`RODiT Authentication Server running on port ${port}`);
    });
  } catch (error) {
    console.error('Server initialization failed:', error);
    process.exit(1);
  }
}

startServer();
```

## Core Concepts

### The RoditClient Pattern

The SDK centers around the `RoditClient` class, which provides a unified interface for all RODiT operations:

- **Single Initialization**: Create once with `RoditClient.create(role)` where role is `'server'`, `'client'`, or `'portal'`
- **Shared Instance**: Store in `app.locals` for access across routes and middleware
- **Self-Configuring**: Automatically loads configuration from Vault, files, or environment variables
- **Encapsulated**: All SDK functionality accessed through the client instance
- **Session Management**: Built-in session tracking with pluggable storage backends
- **Performance Monitoring**: Integrated request tracking and metrics collection

### App.locals Pattern

Store the initialized client in `app.locals` for consistent access across your application:

```javascript
// In main app.js
roditClient = await RoditClient.create('server');
app.locals.roditClient = roditClient;

// In route modules
const router = express.Router();

router.get('/data', (req, res) => {
  const client = req.app.locals.roditClient;
  const logger = client.getLogger();
  
  logger.info('Processing request', {
    component: 'DataRoute',
    userId: req.user?.id
  });
  
  res.json({ data: 'example' });
});
```

### Authentication Middleware Pattern

Create middleware functions that delegate to the RoditClient:

```javascript
// Create reusable middleware
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authenticate(req, res, next);
};

const authorize = (req, res, next) => {
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authorization service unavailable' });
  }
  return client.authorize(req, res, next);
};

// Use in routes
app.get('/api/protected', authenticate, handler);
app.post('/api/admin', authenticate, authorize, adminHandler);
```

## Installation & Setup

### Dependencies

**Required:**
```bash
npm install @rodit/rodit-auth-be express config winston
```

**Recommended for Production:**
```bash
npm install express-session connect-sqlite3
```

**Optional:**
```bash
npm install node-vault  # For Vault-based credentials
npm install winston-loki  # For Grafana Loki logging
```

### Environment Variables

**Vault Configuration (Production):**
```bash
export RODIT_NEAR_CREDENTIALS_SOURCE=vault
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
export SERVICE_NAME=your-service-name
export NEAR_CONTRACT_ID=your-contract.testnet
```

**Application Configuration:**
```bash
export SERVERPORT=3000
export NODE_ENV=production  # Environment: production, development, test
export LOG_LEVEL=info       # Logging: error, warn, info, debug, trace
export API_DEFAULT_OPTIONS_DB_PATH=/app/data/database.sqlite
```

**Logging Configuration:**
```bash
export LOKI_URL=https://loki.example.com:3100
export LOKI_BASIC_AUTH=username:password
```

### Configuration Files

Create `config/default.json`:

```json
{
  "NEAR_CONTRACT_ID": "your-contract.testnet",
  "SERVICE_NAME": "your-service",
  "SERVERPORT": 3000,
  "API_DEFAULT_OPTIONS": {
    "LOG_DIR": "/app/logs",
    "DB_PATH": "/app/data/database.sqlite"
  },
  "SECURITY_OPTIONS": {
    "SILENT_LOGIN_FAILURES": false,
    "JWT_DURATION": 3600
  }
}
```

## Authentication

### RODiT-Based Authentication

RODiT provides cryptographic mutual authentication using blockchain-verified identities.

#### Client Login Request

Clients authenticate by sending RODiT credentials:

```javascript
// POST /api/login
{
  "roditid": "01K4G3D95QF6NR0RSJK9WEK6KA",
  "timestamp": 1640995200,
  "roditid_base64url_signature": "base64url-encoded-signature"
}
```

#### Server Response

```javascript
// Success (200)
{
  "message": "Login successful",
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "requestId": "01HQXYZ123ABC"
}

// Headers:
// Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

#### Authentication Flow

1. **Client sends RODiT credentials** - RODiT ID, timestamp, and cryptographic signature
2. **SDK verifies signature** - Validates against blockchain records (NEAR Protocol)
3. **Session created** - New session stored in session manager
4. **JWT token issued** - Token contains session ID and user claims
5. **Subsequent requests** - Client sends JWT in `Authorization: Bearer <token>` header
6. **Token validation** - SDK validates JWT and checks session status

### Login Implementation

```javascript
// routes/login.js
const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  req.logAction = 'login-attempt';
  
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  
  // Delegate to SDK's login_client method
  await client.login_client(req, res);
});

module.exports = router;
```

### Logout Implementation

```javascript
// Logout invalidates the JWT token and closes the session
router.post('/logout', authenticate, async (req, res) => {
  req.logAction = 'logout-attempt';
  
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  
  // Delegate to SDK's logout_client method
  await client.logout_client(req, res);
});
```

### Protected Routes

```javascript
// Require authentication for access
app.get('/api/data', authenticate, (req, res) => {
  // req.user contains authenticated user information
  const logger = req.app.locals.roditClient.getLogger();
  
  logger.info('Protected route accessed', {
    component: 'API',
    userId: req.user.id,
    roditId: req.user.roditId,
    requestId: req.requestId
  });
  
  res.json({
    message: 'Authenticated data',
    user: req.user,
    requestId: req.requestId
  });
});
```

### Authentication Middleware

The `authenticate` middleware validates JWT tokens and populates `req.user`:

```javascript
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient;
  return client.authenticate(req, res, next);
};

// After successful authentication, req.user contains:
// {
//   id: 'user-unique-id',
//   roditId: '01K4G3D95QF6NR0RSJK9WEK6KA',
//   aud: 'audience',
//   iss: 'issuer',
//   exp: 1640999999,
//   iat: 1640995200,
//   session_id: '01HQXYZ123ABC'
// }
```

## Authorization & Permissions

### Route-Based Permissions

Permissions are configured in your RODiT token metadata using the `permissioned_routes` field:

```json
{
  "permissioned_routes": {
    "entities": {
      "/": {
        "methods": "+0"
      },
      "/api/echo": {
        "methods": "+0"
      },
      "/api/cruda/create": {
        "methods": "+0"
      },
      "/api/cruda/list": {
        "methods": "+0"
      },
      "/api/admin": {
        "methods": "+0"
      }
    }
  }
}
```

**Permission Format:**
- `"+0"` = All methods allowed (GET, POST, PUT, DELETE, etc.)
- `"+1"` = GET only
- `"+2"` = POST only
- Custom combinations can be defined

### Permission Validation Middleware

The `authorize` middleware validates that the authenticated user has permission to access the requested route:

```javascript
const authenticate = (req, res, next) => {
  return req.app.locals.roditClient.authenticate(req, res, next);
};

const authorize = (req, res, next) => {
  return req.app.locals.roditClient.authorize(req, res, next);
};

// Apply both authentication and authorization
app.use('/api/admin', authenticate, authorize, adminRoutes);

// CRUDA endpoints with full protection
app.use('/api/cruda', authenticate, authorize, crudaRoutes);
```

### Permission Enforcement

```javascript
// Example: CRUDA routes with permission checking
const router = express.Router();

// All routes require authentication + authorization
router.post('/create', async (req, res) => {
  // User must have permission for POST /api/cruda/create
  const { comment, author } = req.body;
  
  // Create record in database
  const result = await db.run(
    'INSERT INTO comments (comment, author) VALUES (?, ?)',
    [comment, author || req.user.roditId]
  );
  
  res.json({ id: result.lastID, requestId: req.requestId });
});

router.post('/list', async (req, res) => {
  // User must have permission for POST /api/cruda/list
  const records = await db.all('SELECT * FROM comments ORDER BY created_at DESC');
  res.json({ records, requestId: req.requestId });
});

module.exports = router;
```

### Dynamic Permission Checking

```javascript
// Check permissions programmatically
const client = req.app.locals.roditClient;
const hasPermission = client.isOperationPermitted('POST', '/api/admin/users');

if (!hasPermission) {
  return res.status(403).json({
    error: 'Forbidden',
    message: 'You do not have permission to access this resource',
    requestId: req.requestId
  });
}

// Proceed with operation
```

### Permission Validation in Client Token Minting

When minting client tokens via `/api/signclient`, the server validates that requested permissions are a subset of the server's own permissions:

```javascript
// Client requests these permissions:
const requestedPermissions = {
  "/": "+0",
  "/api/echo": "+0",
  "/api/cruda/create": "+0"
};

// Server validates against its own permissioned_routes
// If any requested route is not in server's config, request is rejected with HTTP 400
```

## Session Management

### Overview

The SDK includes a comprehensive session management system that:
- Tracks active user sessions
- Validates JWT tokens against session state
- Supports pluggable storage backends
- Automatically cleans up expired sessions
- Integrates with performance metrics

### Session Storage Backends

#### 1. In-Memory Storage (Default)

No configuration needed - works out of the box:

```javascript
const client = await RoditClient.create('server');
// Uses InMemorySessionStorage by default
```

**Pros:** Fast, zero configuration  
**Cons:** Sessions lost on server restart, not suitable for multi-server deployments

#### 2. SQLite Storage (Recommended for Production)

Persistent storage using SQLite database:

```javascript
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { RoditClient, setExpressSessionStore } = require('@rodit/rodit-auth-be');

// Configure BEFORE initializing RoditClient
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: './data',
  table: 'sessions'
});

setExpressSessionStore(sessionStore);

// Now initialize client
const client = await RoditClient.create('server');
```

**Pros:** Persistent across restarts, simple setup, uses existing database infrastructure  
**Cons:** Not suitable for multi-server deployments

#### 3. Redis Storage (For Multi-Server)

```bash
npm install express-session connect-redis redis
```

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const { setExpressSessionStore } = require('@rodit/rodit-auth-be');

// Create Redis client
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
});
await redisClient.connect();

// Create Redis store
const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'rodit:sess:',
  ttl: 86400 // 24 hours
});

setExpressSessionStore(redisStore);

const client = await RoditClient.create('server');
```

**Pros:** Shared sessions across multiple servers, high performance  
**Cons:** Requires Redis infrastructure

### Session Operations

```javascript
// Get session manager
const sessionManager = roditClient.getSessionManager();

// Get active session count
const activeCount = await sessionManager.getActiveSessionCount();

// Enumerate sessions via storage
const allSessions = await sessionManager.storage.getAll();
// Or fallback using keys() + get()
const sessionIds = await sessionManager.storage.keys();
const sessions = [];
for (const id of sessionIds) {
  const session = await sessionManager.storage.get(id);
  if (session) sessions.push(session);
}

// Check if token is invalidated
const isInvalidated = await sessionManager.isTokenInvalidated(jwtToken);

// Manually close a session
await sessionManager.closeSession(sessionId);

// Run manual cleanup (removes expired sessions)
const cleanup = await sessionManager.runManualCleanup();
console.log(`Removed ${cleanup.removedSessionsCount} expired sessions`);
```

### Session Lifecycle

1. **Login** - Session created, JWT token issued with session ID
2. **Active** - Token validated on each request, session last_accessed updated
3. **Logout** - Session closed, token invalidated, termination token issued
4. **Expiration** - Sessions automatically expire based on JWT duration
5. **Cleanup** - Expired sessions removed by automatic cleanup process

### Token Invalidation

The SDK validates tokens by checking session state:

```javascript
// Authentication middleware checks:
// 1. JWT signature validity
// 2. JWT expiration
// 3. Session exists and is active
// 4. Session not expired

// After logout, tokens are invalidated because:
// - Session status set to 'closed'
// - Subsequent requests fail authentication
```

## Configuration

### Automatic Configuration Loading

The SDK automatically configures itself from multiple sources (in priority order):

1. **Environment Variables** (Highest priority)
2. **Configuration Files** (config/default.json, config/production.json)
3. **Vault Credentials** (Production)
4. **SDK Defaults** (Fallback)

### Environment Configuration: NODE_ENV and LOG_LEVEL

The SDK uses **two separate environment variables** for configuration, following Node.js ecosystem standards:

#### NODE_ENV - Environment Type & Security Behavior

Controls environment-specific behavior and security settings:

**Values:**
- `production` - Production environment (strict security, no error details)
- `development` - Development environment (relaxed security, detailed errors)
- `test` - Testing environment (allows bypasses for automated testing)
- `staging` - Staging environment (production security with optional verbose logging)

**Default:** `production` (secure by default)

**Controls:**
- ✅ Error detail exposure in API responses
- ✅ Peer public key requirement enforcement
- ✅ Webhook verification bypass (test mode only)
- ✅ Security-critical behavior

#### LOG_LEVEL - Logging Verbosity

Controls Winston logger verbosity independently from environment:

**Values:**
- `error` - Only errors
- `warn` - Warnings and errors
- `info` - Informational messages, warnings, and errors (recommended for production)
- `debug` - Detailed debugging information
- `trace` - Maximum verbosity with full traces

**Default:** `info`

**Controls:**
- ✅ Winston logger output level
- ✅ Debug payload logging
- ✅ Log verbosity only (not security)

#### Separation of Concerns

```javascript
// Environment detection (security)
const isProduction = process.env.NODE_ENV === 'production';
const isDevelopment = process.env.NODE_ENV === 'development';
const isTest = process.env.NODE_ENV === 'test';

// Logging verbosity (independent)
const config = roditClient.getConfig();
const logLevel = config.get('LOG_LEVEL', 'info');
```

#### Configuration Examples

**Production (normal):**
```bash
export NODE_ENV=production
export LOG_LEVEL=info
# Results in:
# - Strict security enforcement
# - No error details in responses
# - Minimal logging output
```

**Production (troubleshooting):**
```bash
export NODE_ENV=production
export LOG_LEVEL=debug
# Results in:
# - Strict security enforcement (still production)
# - No error details in responses (still secure)
# - Verbose logging for debugging
```

**Development:**
```bash
export NODE_ENV=development
export LOG_LEVEL=debug
# Results in:
# - Relaxed security for development
# - Detailed error messages in responses
# - Verbose logging
```

**Testing:**
```bash
export NODE_ENV=test
export LOG_LEVEL=error
# Results in:
# - Test mode (allows bypasses)
# - Detailed error messages
# - Only errors logged (cleaner test output)
```

**Staging:**
```bash
export NODE_ENV=production
export LOG_LEVEL=warn
# Results in:
# - Production security
# - No error details exposed
# - Only warnings and errors logged
```

#### Behavior Matrix

| Scenario | NODE_ENV | LOG_LEVEL | Security | Error Details | Logging |
|----------|----------|-----------|----------|---------------|---------|
| Production | `production` | `info` | ✅ Strict | ❌ Hidden | Minimal |
| Production Debug | `production` | `debug` | ✅ Strict | ❌ Hidden | Verbose |
| Development | `development` | `debug` | ⚠️ Relaxed | ✅ Shown | Verbose |
| Testing | `test` | `error` | ⚠️ Bypass OK | ✅ Shown | Errors only |
| Staging | `production` | `warn` | ✅ Strict | ❌ Hidden | Warnings |

### Vault-Based Configuration (Production)

For production deployments, credentials are loaded from HashiCorp Vault:

```bash
# Environment variables for vault
export RODIT_NEAR_CREDENTIALS_SOURCE=vault
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
export SERVICE_NAME=your-service-name
export NEAR_CONTRACT_ID=your-contract.testnet
```

### File-Based Configuration (Development)

For development, credentials can be loaded from files:

```bash
export RODIT_NEAR_CREDENTIALS_SOURCE=file
export CREDENTIALS_FILE_PATH=./credentials/rodit-credentials.json
```

### Accessing Configuration

```javascript
// Get complete RODiT configuration
const configObject = await roditClient.getConfigOwnRodit();
const metadata = configObject.own_rodit.metadata;

// Access RODiT token metadata
const jwtDuration = metadata.jwt_duration;  // JWT expiration time
const maxRequests = metadata.max_requests;  // Rate limit
const maxRqWindow = metadata.maxrq_window;  // Rate limit window
const apiEndpoint = metadata.subjectuniqueidentifier_url;  // API URL
const webhookUrl = metadata.webhook_url;  // Webhook endpoint

// Parse permissioned routes
const permissionedRoutes = JSON.parse(metadata.permissioned_routes || '{}');

// Use SDK config for application settings
const config = roditClient.getConfig();
const serverPort = config.get('SERVERPORT', 3000);
const logLevel = config.get('LOG_LEVEL', 'info');
const dbPath = config.get('API_DEFAULT_OPTIONS.DB_PATH');
```

### Dynamic Rate Limiting

```javascript
// Configure rate limiting from RODiT token
const configObject = await roditClient.getConfigOwnRodit();
const metadata = configObject.own_rodit.metadata;

if (metadata.max_requests && metadata.maxrq_window) {
  const maxRequests = parseInt(metadata.max_requests);
  const windowSeconds = parseInt(metadata.maxrq_window);
  
  const rateLimiter = roditClient.getRateLimitMiddleware();
  app.use(rateLimiter(maxRequests, windowSeconds));
}
```

## Logging & Monitoring

### Structured Logging

The SDK provides comprehensive structured logging:

```javascript
const { logger } = require('@rodit/rodit-auth-be');

// Basic logging
logger.info('Operation completed', {
  component: 'UserService',
  operation: 'createUser',
  userId: '123',
  duration: 150
});

// Context-aware logging
logger.infoWithContext('Request processed', {
  component: 'API',
  method: 'POST',
  path: '/api/users',
  requestId: req.requestId,
  userId: req.user?.id,
  duration: Date.now() - req.startTime
});

// Error logging with metrics
logger.errorWithContext('Operation failed', {
  component: 'UserService',
  operation: 'createUser',
  requestId: req.requestId,
  error: error.message,
  stack: error.stack
}, error);
```

### Loki with the SDK (canonical)

Use this as the authoritative guide for configuring logging with the SDK.

#### Environment variables

```bash
export LOKI_URL=https://<your-loki-host>:3100
export LOKI_BASIC_AUTH="username:password"   # store in secrets
export LOKI_TLS_SKIP_VERIFY=true              # only for self-signed/test
export LOG_LEVEL=info
export SERVICE_NAME=clienttestapi-api
```

These are already mapped in `config/custom-environment-variables.json`, so container/CI env vars will flow into the app.

#### How the SDK selects/configures the logger

- Default: JSON to stdout only (no Loki). Honors `LOG_LEVEL`, adds `service_name`.
- Production: Create a Winston logger with a `winston-loki` transport and inject it once: `logger.setLogger(customLogger)`.
- Access: `const { logger } = require('@rodit/rodit-auth-be')` or `roditClient.getLogger()` both delegate to the same facade.

#### Direct-to-Loki via winston-loki (recommended)

```javascript
const { logger } = require('@rodit/rodit-auth-be');
const winston = require('winston');
const LokiTransport = require('winston-loki');

const transports = [new winston.transports.Console({ format: winston.format.json() })];

if (process.env.LOKI_URL) {
  const lokiOptions = {
    host: process.env.LOKI_URL,
    basicAuth: process.env.LOKI_BASIC_AUTH, // Basic Auth for Loki
    labels: { app: process.env.SERVICE_NAME || 'clienttestapi-api', component: 'rodit-sdk' },
    json: true,
    batching: true
  };
  if ((process.env.LOKI_TLS_SKIP_VERIFY || '').toLowerCase() === 'true') {
    lokiOptions.ssl = { rejectUnauthorized: false };
  }
  transports.push(new LokiTransport(lokiOptions));
}

const customLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports
});

logger.setLogger(customLogger);
```

#### Promtail (optional alternative)

- Only needed if you must ship file logs (e.g., Nginx) or cannot push directly from the process.
- SDK logs do not need Promtail when using `winston-loki`.
- If you keep Promtail, ensure the scrape path matches files (see `promtail/promtail-config.yml`).

#### CI/CD notes

- `.github/workflows/deploy.yml` passes `LOKI_URL`, `LOKI_TLS_SKIP_VERIFY`, `LOKI_BASIC_AUTH` into the container; `src/app.js` config injects the transport at startup.
- Promtail steps are commented out. If you don’t need file-based ingestion, you can remove Promtail steps and the `promtail/` directory entirely. Keep it only for Nginx/file logs.
- Store `LOKI_BASIC_AUTH` in CI/CD secrets; never commit credentials.

#### Quick verification

 1) Start the app with `LOKI_URL` and `LOKI_BASIC_AUTH` set.
 2) Emit a test log: `logger.info('Loki test', { component: 'SmokeTest' })`.
 3) In Grafana Explore, query with `{app="clienttestapi-api"}` and confirm logs.

 ## Webhooks
 
 ### Overview

The SDK supports sending webhooks for important events. Webhook URLs are configured in the RODiT token metadata.
Webhooks are configured in your RODiT token:

```json
{
  "webhook_url": "https://webhook.example.com:3444",
  "webhook_cidr": "0.0.0.0/0"
}
```

### Sending Webhooks

```javascript
// Get webhook handler from client
const roditClient = req.app.locals.roditClient;

// Send webhook for an event
const webhookPayload = {
  event: 'comment_created',
  data: {
    id: comment.id,
    author: comment.author,
    timestamp: new Date().toISOString()
  },
  isError: false
};

try {
  const result = await roditClient.send_webhook(webhookPayload, req);
  
  if (result.success) {
    logger.info('Webhook sent successfully', {
      component: 'CRUDA',
      event: webhookPayload.event,
      requestId: req.requestId
    });
  }
} catch (error) {
  // Webhook failures don't crash the application
  logger.warn('Webhook delivery failed', {
    component: 'CRUDA',
    event: webhookPayload.event,
    error: error.message,
    requestId: req.requestId
  });
}
```

### Webhook Error Handling

```javascript
// Graceful webhook handling in CRUDA operations
const logAndSendWebhook = async (payload, req = null) => {
  try {
    const roditClient = req?.app?.locals?.roditClient;
    
    if (!roditClient) {
      logger.warn('RoditClient not available, skipping webhook', {
        component: 'CRUDA',
        event: payload?.event
      });
      return { success: false, error: 'RoditClient not available' };
    }
    
    return await roditClient.send_webhook(payload, req);
  } catch (error) {
    // Log but don't throw - webhook failures shouldn't crash the app
    logger.error('Webhook delivery failed', {
      component: 'CRUDA',
      event: payload?.event,
      error: error.message
    });
    return { success: false, error: error.message };
  }
};
```

## Advanced Usage

### Route Module Pattern

Create reusable route modules that access the shared RoditClient:

```javascript
// routes/protected.js
const express = require('express');
const { logger } = require('@rodit/rodit-auth-be');
const router = express.Router();

// Middleware that uses the shared client
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authenticate(req, res, next);
};

const authorize = (req, res, next) => {
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authorize(req, res, next);
};

// Protected route with full authentication and authorization
router.get('/data', authenticate, authorize, async (req, res) => {
  const startTime = Date.now();
  
  try {
    // Your business logic here
    const data = await processUserData(req.user.id);
    
    logger.infoWithContext('Data retrieved successfully', {
      component: 'ProtectedRoutes',
      method: 'getData',
      userId: req.user.id,
      requestId: req.requestId,
      duration: Date.now() - startTime
    });
    
    res.json({ data, requestId: req.requestId });
  } catch (error) {
    logger.errorWithContext('Failed to retrieve data', {
      component: 'ProtectedRoutes',
      method: 'getData',
      userId: req.user.id,
      requestId: req.requestId,
      duration: Date.now() - startTime,
      error: error.message
    }, error);
    
    res.status(500).json({
      error: 'Internal server error',
      requestId: req.requestId
    });
  }
});

module.exports = router;
```

### Portal Authentication (Server-to-Server)

For server-to-server authentication (e.g., minting client tokens):

```javascript
// routes/signclient.js
const router = express.Router();

router.post('/signclient', authenticate, authorize, async (req, res) => {
  const { tobesignedValues, mintingfee, mintingfeeaccount } = req.body;
  const client = req.app.locals.roditClient;
  const logger = client.getLogger();
  
  try {
    // Validate requested permissions against server's permissions
    const configObject = await client.getConfigOwnRodit();
    const serverPermissions = JSON.parse(
      configObject.own_rodit.metadata.permissioned_routes || '{}'
    );
    
    const requestedPermissions = JSON.parse(
      tobesignedValues.permissioned_routes || '{}'
    );
    
    // Validate that all requested routes exist in server config
    // (Implementation details in actual code)
    
    // Authenticate to portal and mint client token
    const port = configObject.port || 8443;
    const result = await client.login_portal(configObject, port);
    
    if (result.error) {
      return res.status(500).json({
        error: 'Portal authentication failed',
        details: result.message,
        requestId: req.requestId
      });
    }
    
    // Sign the client token via portal
    const signedToken = await signPortalRodit(
      port,
      tobesignedValues,
      mintingfee,
      mintingfeeaccount,
      client
    );
    
    res.json({
      signedToken,
      requestId: req.requestId
    });
  } catch (error) {
    logger.errorWithContext('Client token minting failed', {
      component: 'SignClient',
      requestId: req.requestId,
      error: error.message
    }, error);
    
    res.status(500).json({
      error: 'Token minting failed',
      requestId: req.requestId
    });
  }
});

module.exports = router;
```

### CRUDA Operations Example

Complete CRUD implementation with authentication, authorization, webhooks, and performance tracking:

```javascript
// protected/cruda.js
const express = require('express');
const router = express.Router();
const { RoditClient } = require('@rodit/rodit-auth-be');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const { ulid } = require('ulid');

const sdkClient = new RoditClient();
const logger = sdkClient.getLogger();

let db;

// Initialize database
const initializeDatabase = async () => {
  db = await open({
    filename: '/app/data/database.sqlite',
    driver: sqlite3.Database
  });
  
  await db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment TEXT NOT NULL,
    author TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
};

// Webhook helper
const logAndSendWebhook = async (payload, req) => {
  try {
    const roditClient = req?.app?.locals?.roditClient;
    if (!roditClient) return { success: false };
    
    return await roditClient.send_webhook(payload, req);
  } catch (error) {
    logger.error('Webhook failed', { error: error.message });
    return { success: false, error: error.message };
  }
};

// CREATE
router.post('/create', async (req, res) => {
  const { comment, author } = req.body;
  const requestId = req.requestId || ulid();
  
  try {
    const result = await db.run(
      'INSERT INTO comments (comment, author) VALUES (?, ?)',
      [comment, author || req.user.roditId]
    );
    
    // Send webhook
    await logAndSendWebhook({
      event: 'comment_created',
      data: { id: result.lastID, comment, author },
      isError: false
    }, req);
    
    res.json({ id: result.lastID, requestId });
  } catch (error) {
    logger.errorWithContext('Create failed', {
      component: 'CRUDA',
      error: error.message,
      requestId
    }, error);
    
    res.status(500).json({ error: 'Create failed', requestId });
  }
});

// LIST
router.post('/list', async (req, res) => {
  try {
    const records = await db.all(
      'SELECT * FROM comments ORDER BY created_at DESC'
    );
    
    res.json({ records, requestId: req.requestId });
  } catch (error) {
    res.status(500).json({ error: 'List failed', requestId: req.requestId });
  }
});

// READ
router.post('/read', async (req, res) => {
  const { id } = req.body;
  
  try {
    const record = await db.get('SELECT * FROM comments WHERE id = ?', [id]);
    
    if (!record) {
      return res.status(404).json({ error: 'Not found', requestId: req.requestId });
    }
    
    res.json({ record, requestId: req.requestId });
  } catch (error) {
    res.status(500).json({ error: 'Read failed', requestId: req.requestId });
  }
});

// UPDATE
router.post('/update', async (req, res) => {
  const { id, comment } = req.body;
  
  try {
    await db.run(
      'UPDATE comments SET comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [comment, id]
    );
    
    await logAndSendWebhook({
      event: 'comment_updated',
      data: { id, comment },
      isError: false
    }, req);
    
    res.json({ success: true, requestId: req.requestId });
  } catch (error) {
    res.status(500).json({ error: 'Update failed', requestId: req.requestId });
  }
});

// DELETE
router.post('/destroy', async (req, res) => {
  const { id } = req.body;
  
  try {
    await db.run('DELETE FROM comments WHERE id = ?', [id]);
    
    await logAndSendWebhook({
      event: 'comment_deleted',
      data: { id },
      isError: false
    }, req);
    
    res.json({ success: true, requestId: req.requestId });
  } catch (error) {
    res.status(500).json({ error: 'Delete failed', requestId: req.requestId });
  }
});

// Export initialization function
module.exports = router;
module.exports.initializeDatabase = initializeDatabase;
```

## API Reference

### RoditClient Class

The main client class for all RODiT operations.

#### Static Methods

##### RoditClient.create(role)

Create and initialize a RODiT client in one step.

```javascript
const client = await RoditClient.create('server');  // For server applications
const client = await RoditClient.create('client');  // For client applications
const client = await RoditClient.create('portal');  // For portal authentication
```

**Parameters:**
- `role` (string): Client role - `'server'`, `'client'`, or `'portal'`

**Returns:** `Promise<RoditClient>` - Fully initialized client instance

**Throws:** Error if initialization fails (e.g., missing credentials, Vault connection failure)

#### Instance Methods

##### authenticate(req, res, next)

Express middleware for authenticating API requests. Validates JWT tokens and populates `req.user`.

```javascript
const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
app.use('/api/protected', authenticate, handler);
```

**Validates:**
- JWT signature
- JWT expiration
- Session exists and is active
- Token not invalidated

**Populates:** `req.user` with decoded JWT claims

##### authorize(req, res, next)

Express middleware for validating route permissions. Must be used after `authenticate`.

```javascript
const authorize = (req, res, next) => roditClient.authorize(req, res, next);
app.use('/api/admin', authenticate, authorize, handler);
```

**Validates:** User has permission for the requested route and HTTP method

##### login_client(req, res)

Handle Express login requests from clients. Validates RODiT credentials and issues JWT token.

```javascript
app.post('/api/login', (req, res) => roditClient.login_client(req, res));
```

**Request Body:**
```javascript
{
  roditid: string,
  timestamp: number,
  roditid_base64url_signature: string
}
```

**Response:**
```javascript
{
  message: 'Login successful',
  token: 'eyJhbGci...',
  requestId: '01HQXYZ...'
}
```

##### logout_client(req, res)

Handle Express logout requests. Closes session and invalidates JWT token.

```javascript
app.post('/api/logout', authenticate, (req, res) => {
  return roditClient.logout_client(req, res);
});
```

**Response:**
```javascript
{
  message: 'Logout successful',
  terminationToken: 'eyJhbGci...',  // Short-lived token
  requestId: '01HQXYZ...'
}
```

##### login_portal(configObject, port)

Authenticate to RODiT portal for server-to-server operations.

```javascript
const configObject = await roditClient.getConfigOwnRodit();
const result = await roditClient.login_portal(configObject, 8443);
```

**Returns:** `Promise<Object>` - Portal authentication result

##### login_server(options)

Authenticate this server to another RODiT server.

```javascript
const result = await roditClient.login_server({
  serverUrl: 'https://api.example.com',
  credentials: {...}
});
```

**Returns:** `Promise<Object>` - Authentication result with token

##### logout_server()

Logout from server-to-server session.

```javascript
const result = await roditClient.logout_server();
```

**Returns:** `Promise<Object>` - Logout result with session closure status

##### getConfigOwnRodit()

Get the complete RODiT configuration including token metadata.

```javascript
const configObject = await roditClient.getConfigOwnRodit();
const metadata = configObject.own_rodit.metadata;
const tokenId = configObject.own_rodit.token_id;
```

**Returns:** `Promise<Object>` - Complete RODiT configuration

**Structure:**
```javascript
{
  own_rodit: {
    token_id: string,
    metadata: {
      jwt_duration: number,
      max_requests: string,
      maxrq_window: string,
      permissioned_routes: string,  // JSON string
      subjectuniqueidentifier_url: string,
      webhook_url: string,
      // ... other metadata fields
    }
  },
  port: number
}
```

##### isOperationPermitted(method, path)

Check if an operation is permitted based on token permissions.

```javascript
const hasPermission = roditClient.isOperationPermitted('POST', '/api/admin/users');
if (!hasPermission) {
  return res.status(403).json({ error: 'Forbidden' });
}
```

**Parameters:**
- `method` (string): HTTP method
- `path` (string): API path

**Returns:** `boolean`

##### getStateManager()

Get the authentication state manager.

```javascript
const stateManager = roditClient.getStateManager();
```

**Returns:** `AuthStateManager` instance

##### getRoditManager()

Get the RODiT manager for credential operations.

```javascript
const roditManager = roditClient.getRoditManager();
const credentials = await roditManager.getCredentials('server');
```

**Returns:** `RoditManager` instance

##### getSessionManager()

Get the session manager.

```javascript
const sessionManager = roditClient.getSessionManager();
const activeCount = await sessionManager.getActiveSessionCount();
```

**Returns:** `SessionManager` instance

##### getLogger()

Get the logger instance.

```javascript
const logger = roditClient.getLogger();
logger.info('Message', { component: 'MyComponent' });
```

**Returns:** `Logger` instance

##### getLoggingMiddleware()

Get the logging middleware.

```javascript
const loggingmw = roditClient.getLoggingMiddleware();
app.use(loggingmw);
```

**Returns:** Express middleware function

##### getRateLimitMiddleware()

Get the rate limiting middleware factory.

```javascript
const ratelimitmw = roditClient.getRateLimitMiddleware();
const limiter = ratelimitmw(100, 900);  // 100 requests per 15 minutes
app.use(limiter);
```

**Parameters:**
- `maxRequests` (number): Maximum requests allowed
- `windowSeconds` (number): Time window in seconds

**Returns:** Express middleware function

##### getPerformanceService()

Get the performance tracking service.

```javascript
const performanceService = roditClient.getPerformanceService();
performanceService.recordRequest(req);
performanceService.recordMetric('operation_duration', 150, { operation: 'db_query' });
```

**Returns:** `PerformanceService` instance

##### getConfig()

Get the configuration service.

```javascript
const config = roditClient.getConfig();
const port = config.get('SERVERPORT', 3000);
const dbPath = config.get('API_DEFAULT_OPTIONS.DB_PATH');
```

**Returns:** `Config` instance

##### getWebhookHandler()

Get the webhook handler.

```javascript
const webhookHandler = roditClient.getWebhookHandler();
```

**Returns:** `WebhookHandler` instance

##### send_webhook(payload, req)

Send a webhook notification.

```javascript
const result = await roditClient.send_webhook({
  event: 'user_action',
  data: { userId: '123', action: 'login' },
  isError: false
}, req);
```

**Parameters:**
- `payload` (Object): Webhook payload
  - `event` (string): Event name
  - `data` (Object): Event data
  - `isError` (boolean): Whether this is an error event
- `req` (Object): Express request object (optional)

**Returns:** `Promise<Object>` - `{ success: boolean, ... }`

### Exported Components

The SDK exports these components for direct use:

```javascript
const {
  RoditClient,           // Main client class
  logger,                // Logger instance
  stateManager,          // Authentication state manager
  roditManager,          // RODiT credential manager
  sessionManager,        // Session manager
  setExpressSessionStore, // Configure session storage
  configureStorageFromConfig, // Auto-configure storage
  createExpressSessionMiddleware, // Create session middleware
  InMemorySessionStorage, // Default storage class
  SessionManager,        // SessionManager facade
  blockchainService,     // Blockchain operations
  utils,                 // Utility functions
  config,                // Configuration service
  performanceService,    // Performance tracking
  authenticate_apicall,  // Authentication middleware
  login_client,          // Login handler
  logout_client,         // Logout handler
  login_client_withnep413, // NEP-413 login
  login_portal,          // Portal authentication
  login_server,          // Server authentication
  logout_server,         // Server logout
  validate_jwt_token_be, // JWT validation
  generate_jwt_token,    // JWT generation
  validatepermissions,   // Permission middleware
  webhookHandler,        // Webhook handler
  versioningMiddleware,  // API versioning
  loggingmw,             // Logging middleware
  ratelimitmw,           // Rate limiting middleware
  versionManager,        // Version manager
  VersionManager         // Version manager class
} = require('@rodit/rodit-auth-be');
```

### RODiT Token Metadata Fields

When you call `roditClient.getConfigOwnRodit()`, you get access to these metadata fields:

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string | Unique RODiT token identifier |
| `allowed_cidr` | string | Permitted IP address ranges (CIDR format) |
| `allowed_iso3166list` | string | Geographic restrictions (JSON string) |
| `jwt_duration` | number | JWT token lifetime in seconds |
| `max_requests` | string | Rate limit - maximum requests per window |
| `maxrq_window` | string | Rate limit - time window in seconds |
| `not_before` | string | Token validity start date (ISO format) |
| `not_after` | string | Token validity end date (ISO format) |
| `openapijson_url` | string | OpenAPI specification URL |
| `permissioned_routes` | string | Allowed API routes and methods (JSON string) |
| `serviceprovider_id` | string | Blockchain contract and service provider info |
| `serviceprovider_signature` | string | Cryptographic signature for verification |
| `subjectuniqueidentifier_url` | string | Primary API service endpoint |
| `userselected_dn` | string | User-selected display name |
| `webhook_cidr` | string | Allowed IP ranges for webhooks |
| `webhook_url` | string | Webhook endpoint URL |

## Best Practices

### 1. Single Client Initialization

Always initialize the RoditClient once in your main application file:

```javascript
// ✅ Good - Single initialization
async function startServer() {
  const roditClient = await RoditClient.create('server');
  app.locals.roditClient = roditClient;
  
  // Mount protected routes AFTER client initialization
  const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
  const authorize = (req, res, next) => roditClient.authorize(req, res, next);
  
  app.use('/api/echo', authenticate, echoRoutes);
  app.use('/api/cruda', authenticate, authorize, crudaRoutes);
  
  // ... rest of server setup
}

// ❌ Bad - Multiple initializations
app.get('/route1', async (req, res) => {
  const client = await RoditClient.create('server'); // Don't do this
});
```

### 2. Use App.locals for Shared Access

Store the client in `app.locals` for access across all routes:

```javascript
// ✅ Good - Shared instance via app.locals
const router = express.Router();

router.get('/data', (req, res) => {
  const client = req.app.locals.roditClient;
  const logger = client.getLogger();
  
  logger.info('Processing request', {
    component: 'DataRoute',
    userId: req.user?.id,
    requestId: req.requestId
  });
  
  res.json({ data: 'example' });
});

// ❌ Bad - Creating new instances in routes
const { RoditClient } = require('@rodit/rodit-auth-be');
const client = new RoditClient(); // Don't do this in routes
```

### 3. Proper Error Handling

Always wrap SDK operations in try-catch blocks and include request context:

```javascript
// ✅ Good - Comprehensive error handling
app.get('/api/data', authenticate, async (req, res) => {
  const startTime = Date.now();
  const client = req.app.locals.roditClient;
  const logger = client.getLogger();
  
  try {
    const data = await processData(req.user.id);
    
    logger.infoWithContext('Request successful', {
      component: 'API',
      method: 'getData',
      userId: req.user.id,
      requestId: req.requestId,
      duration: Date.now() - startTime
    });
    
    res.json({ data, requestId: req.requestId });
  } catch (error) {
    logger.errorWithContext('Request failed', {
      component: 'API',
      method: 'getData',
      userId: req.user.id,
      requestId: req.requestId,
      duration: Date.now() - startTime,
      error: error.message
    }, error);
    
    res.status(500).json({
      error: 'Internal server error',
      requestId: req.requestId
    });
  }
});
```

### 4. Structured Logging

Use consistent logging patterns with context:

```javascript
// ✅ Good - Structured logging with context
const logger = req.app.locals.roditClient.getLogger();

logger.infoWithContext('User action completed', {
  component: 'UserService',
  action: 'updateProfile',
  userId: user.id,
  requestId: req.requestId,
  duration: Date.now() - startTime,
  changes: Object.keys(updates)
});

// For errors, pass the error object
logger.errorWithContext('Operation failed', {
  component: 'UserService',
  action: 'updateProfile',
  userId: user.id,
  requestId: req.requestId,
  error: error.message
}, error);

// ❌ Bad - Unstructured logging
console.log('User updated profile'); // Don't do this
```

### 5. Environment-Specific Configuration

Use environment variables for sensitive and environment-specific values:

```javascript
// ✅ Good - Environment-aware configuration
const config = roditClient.getConfig();
const logLevel = config.get('LOG_LEVEL', 'info');
const isProduction = ['info', 'warn', 'error'].includes(logLevel);

// Production should use vault credentials
if (isProduction && process.env.RODIT_NEAR_CREDENTIALS_SOURCE !== 'vault') {
  logger.warn('Production environment should use vault credentials', {
    component: 'Configuration',
    environment: 'production',
    credentialsSource: process.env.RODIT_NEAR_CREDENTIALS_SOURCE || 'not-set'
  });
}

// Configure session storage before initializing client
if (isProduction) {
  const SQLiteStore = require('connect-sqlite3')(require('express-session'));
  const sessionStore = new SQLiteStore({
    db: 'sessions.db',
    dir: config.get('API_DEFAULT_OPTIONS.DB_PATH', './data')
  });
  setExpressSessionStore(sessionStore);
}
```

### 6. Graceful Shutdown

Implement proper shutdown handling:

```javascript
// ✅ Good - Graceful shutdown
const shutdown = async (signal) => {
  const logger = roditClient.getLogger();
  
  logger.info('Shutting down gracefully', {
    component: 'AppLifecycle',
    signal: signal || 'unknown',
    time: new Date().toISOString()
  });
  
  if (server) {
    server.close(async () => {
      logger.info('HTTP server closed');
      
      // Close database connections
      if (db && typeof db.close === 'function') {
        await db.close();
        logger.info('Database connections closed');
      }
      
      // Close session store
      if (sessionStore && typeof sessionStore.close === 'function') {
        await new Promise((resolve) => sessionStore.close(resolve));
        logger.info('Session store closed');
      }
      
      process.exit(0);
    });
    
    // Force shutdown after timeout
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  }
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
```

### 7. Request Context and Performance Tracking

Always include request context and track performance:

```javascript
// ✅ Good - Request context and performance tracking
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || ulid();
  req.startTime = Date.now();
  next();
});

// Performance monitoring
app.use((req, res, next) => {
  const performanceService = roditClient.getPerformanceService();
  
  if (performanceService) {
    performanceService.recordRequest(req);
  }
  
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    
    if (performanceService) {
      performanceService.recordMetric('request_duration_ms', duration, {
        method: req.method,
        path: req.path,
        status: res.statusCode
      });
      
      if (res.statusCode >= 400) {
        performanceService.recordMetric('error_count', 1, {
          method: req.method,
          path: req.path,
          status: res.statusCode
        });
      }
    }
  });
  
  next();
});
```

### 8. Login Endpoint Protection

**CRITICAL:** Never protect the login endpoint with authentication middleware:

```javascript
// ✅ Good - Login endpoint without authentication
app.post('/api/login', (req, res) => {
  req.logAction = 'login-attempt';
  return roditClient.login_client(req, res);
});

// ❌ Bad - Login endpoint with authentication (creates circular dependency)
app.post('/api/login', authenticate, (req, res) => {  // DON'T DO THIS
  return roditClient.login_client(req, res);
});

// ✅ Good - Logout endpoint with authentication
app.post('/api/logout', authenticate, (req, res) => {
  req.logAction = 'logout-attempt';
  return roditClient.logout_client(req, res);
});
```

### 9. Route Mounting Order

Mount protected routes AFTER client initialization:

```javascript
// ✅ Good - Correct order
async function startServer() {
  // 1. Configure session storage
  setExpressSessionStore(sessionStore);
  
  // 2. Initialize client
  roditClient = await RoditClient.create('server');
  app.locals.roditClient = roditClient;
  
  // 3. Create middleware
  const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
  const authorize = (req, res, next) => roditClient.authorize(req, res, next);
  
  // 4. Mount public routes
  app.post('/api/login', loginRoute);
  
  // 5. Mount protected routes
  app.use('/api/echo', authenticate, echoRoutes);
  app.use('/api/cruda', authenticate, authorize, crudaRoutes);
  app.post('/api/logout', authenticate, logoutRoute);
  
  // 6. Start server
  app.listen(port);
}

// ❌ Bad - Routes mounted before client initialization
app.use('/api/echo', authenticate, echoRoutes);  // authenticate is undefined!
roditClient = await RoditClient.create('server');
```

## Troubleshooting

### Common Issues

#### 1. Authentication Middleware Errors

**Problem:** `roditClient.authenticate is not a function` or `Cannot read properties of undefined`

**Solution:** Ensure client is initialized and stored in app.locals:
```javascript
// ✅ Correct - Check client availability
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authenticate(req, res, next);
};

// ❌ Wrong - Direct access without checking
const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
// This fails if roditClient is not initialized yet
```

#### 2. Configuration Not Found

**Problem:** `Failed to initialize RODiT configuration`

**Solutions:**
```bash
# Check environment variables
echo $RODIT_NEAR_CREDENTIALS_SOURCE  # Should be 'vault' or 'file'
echo $VAULT_ENDPOINT
echo $NEAR_CONTRACT_ID
echo $SERVICE_NAME

# For vault-based credentials
export RODIT_NEAR_CREDENTIALS_SOURCE=vault
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id

# For file-based credentials (development)
export RODIT_NEAR_CREDENTIALS_SOURCE=file
export CREDENTIALS_FILE_PATH=./credentials/rodit-credentials.json
```

**Verify configuration:**
```javascript
const config = roditClient.getConfig();
console.log('NEAR_CONTRACT_ID:', config.get('NEAR_CONTRACT_ID'));
console.log('SERVICE_NAME:', config.get('SERVICE_NAME'));
```

#### 3. Missing App.locals Client

**Problem:** `RoditClient not available in app.locals` or `Cannot read properties of undefined (reading 'roditClient')`

**Solution:** Ensure client is stored during initialization:
```javascript
async function startServer() {
  try {
    // Initialize client
    const roditClient = await RoditClient.create('server');
    
    // Store in app.locals BEFORE mounting routes
    app.locals.roditClient = roditClient;
    
    // Verify it's stored
    if (!app.locals.roditClient) {
      throw new Error('Failed to store roditClient in app.locals');
    }
    
    // Now mount routes
    const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
    app.use('/api/protected', authenticate, protectedRoutes);
    
    app.listen(port);
  } catch (error) {
    console.error('Server initialization failed:', error);
    process.exit(1);
  }
}
```

#### 4. Permission Denied Errors

**Problem:** Routes return 403 Forbidden

**Debug steps:**
```javascript
// Check token permissions
const configObject = await roditClient.getConfigOwnRodit();
const permissionedRoutes = JSON.parse(
  configObject.own_rodit.metadata.permissioned_routes || '{}'
);
console.log('Configured permissions:', permissionedRoutes);

// Check specific operation
const hasPermission = roditClient.isOperationPermitted('POST', '/api/cruda/create');
console.log('Has permission:', hasPermission);

// Verify route path matches exactly
console.log('Requested path:', req.path);  // Must match permission key exactly
```

**Common issues:**
- Route path doesn't match permission key exactly (e.g., `/api/cruda/create` vs `/cruda/create`)
- HTTP method not allowed in permission configuration
- Permission format incorrect (should be `"+0"` for all methods)
- Client token has different permissions than server token

#### 5. Session Not Found Errors

**Problem:** `401 Unauthorized - session_not_found`

**Cause:** JWT token contains session ID that doesn't exist in session storage

**Solutions:**
```javascript
// Verify session storage is configured
const sessionManager = roditClient.getSessionManager();
const storageInfo = await sessionManager.getStorageInfo();
console.log('Storage type:', storageInfo.storageType);
console.log('Active sessions:', storageInfo.sessionCount);

// Check if token is invalidated
const isInvalidated = await sessionManager.isTokenInvalidated(jwtToken);
console.log('Token invalidated:', isInvalidated);

// Enumerate sessions via storage for debugging
const allSessions = await sessionManager.storage.getAll();
console.log('Active sessions:', allSessions.filter(s => s.status === 'active').length);
```

**Common causes:**
- Server restarted with in-memory storage (sessions lost)
- Session expired
- Token was invalidated by logout
- Session storage not configured properly

**Solution:** Use persistent storage (SQLite or Redis) for production

#### 6. Logging Issues

**Problem:** Logs not appearing in Loki or console

**Solutions:**
```bash
# Check logging configuration
export LOG_LEVEL=debug  # Enable debug logging
export LOKI_URL=https://loki.example.com:3100
export LOKI_BASIC_AUTH=username:password
```

```javascript
// Test logger directly
const logger = roditClient.getLogger();
logger.info('Test message', { component: 'Test' });
logger.error('Test error', { component: 'Test' });

// Check if Loki transport is configured
const transports = logger.transports;
console.log('Logger transports:', transports.map(t => t.name));
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
export LOG_LEVEL=debug  # Use 'debug' or 'trace' for development mode
```

This will provide detailed information about:
- Authentication flows and token validation
- Configuration loading from Vault/files
- Permission checks and route matching
- Session creation and validation
- Network requests to portal/blockchain
- Internal SDK operations
- Request/response details

**Example debug output:**
```javascript
const logger = roditClient.getLogger();

// Enable debug logging programmatically
logger.level = 'debug';

// Debug authentication
logger.debug('Authenticating request', {
  component: 'Authentication',
  hasAuthHeader: !!req.headers.authorization,
  path: req.path,
  method: req.method
});
```

### Health Checks

Implement comprehensive health check endpoints:

```javascript
app.get('/health', async (req, res) => {
  try {
    const client = req.app.locals.roditClient;
    if (!client) {
      return res.status(503).json({ 
        status: 'error', 
        message: 'RoditClient not available' 
      });
    }
    
    const configObject = await client.getConfigOwnRodit();
    const sessionManager = client.getSessionManager();
    const performanceService = client.getPerformanceService();
    
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      logLevel: config.get('LOG_LEVEL', 'info'),
      components: {
        roditClient: !!client,
        configuration: !!(configObject && configObject.own_rodit),
        sessionManager: !!sessionManager,
        performanceService: !!performanceService
      },
      metrics: {
        activeSessions: await sessionManager.getActiveSessionCount(),
        totalRequests: performanceService.getRequestCount(),
        errorCount: performanceService.getErrorCount()
      },
      roditToken: {
        tokenId: configObject?.own_rodit?.token_id,
        apiUrl: configObject?.own_rodit?.metadata?.subjectuniqueidentifier_url,
        jwtDuration: configObject?.own_rodit?.metadata?.jwt_duration
      }
    };
    
    res.json(health);
  } catch (error) {
    res.status(503).json({
      status: 'error',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Readiness check (for Kubernetes)
app.get('/ready', async (req, res) => {
  const client = req.app.locals.roditClient;
  if (!client) {
    return res.status(503).json({ ready: false });
  }
  
  try {
    const configObject = await client.getConfigOwnRodit();
    const ready = !!(configObject && configObject.own_rodit);
    
    res.status(ready ? 200 : 503).json({ ready });
  } catch (error) {
    res.status(503).json({ ready: false, error: error.message });
  }
});

// Liveness check (for Kubernetes)
app.get('/live', (req, res) => {
  res.json({ alive: true });
});
```

### Support

For additional support:
1. Check the debug logs with `LOG_LEVEL=debug`
2. Verify your RODiT token configuration
3. Test with the health check endpoint
4. Review the authentication flow in the logs
5. Ensure all required environment variables are set

---

## License

Copyright (c) 2025 Discernible Inc. All rights reserved.
