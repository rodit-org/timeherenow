# Authorization Flow Analysis: Server vs Client Permissions

## Overview

The Time Here Now API uses a **two-tier authorization system** implemented by the `@rodit/rodit-auth-be` SDK:

1. **Authentication** (`authenticate` middleware) - Validates JWT token and checks route permissions
2. **Authorization** (`authorize` middleware) - Checks admin/special permissions

---

## Permission Cross-Reference Flow

### Step 1: Client Requests Access (Token Minting)

When a client requests a new RODIT token via `/api/signclient`:

```javascript
// Client sends requested permissions
{
  "tobesignedValues": {
    "permissioned_routes": "{\"entities\": {\"methods\": {\"/api/timezone\": \"+0\"}}}"
  }
}
```

### Step 2: Server Validates Against Its Own RODIT

```javascript
// From signclient.js lines 279-327
const requestedPermissions = JSON.parse(tobesignedValues.permissioned_routes);
const configPermissions = JSON.parse(config_own_rodit.own_rodit.metadata.permissioned_routes);

const requestedMethods = requestedPermissions?.entities?.methods || {};
const configMethods = configPermissions?.entities?.methods || {};

// Check each requested route
for (const route of Object.keys(requestedMethods)) {
  if (!configMethods.hasOwnProperty(route)) {
    invalidRoutes.push(route);
  }
}

// Reject if any invalid routes
if (invalidRoutes.length > 0) {
  return res.status(400).json({
    error: "Invalid permissions requested",
    details: { invalidRoutes, availableRoutes: Object.keys(configMethods) }
  });
}
```

**Result**: Client can only get permissions that are a **subset** of server's permissions.

### Step 3: Token is Signed and Issued

If validation passes, the token is signed by the SignPortal with the requested permissions embedded in the token metadata.

### Step 4: Client Uses Token for API Requests

Client includes the JWT token in requests:

```http
GET /api/timezone HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Step 5: SDK Validates on Each Request

The `authenticate` middleware (from `@rodit/rodit-auth-be`) performs:

```javascript
// From app.js line 255
app.use("/api", app.locals.roditClient.authenticate);
```

**What `authenticate` does** (implemented in SDK):
1. ✅ Validates JWT signature
2. ✅ Checks token expiration (`not_before`, `not_after`)
3. ✅ Validates network restrictions (`allowed_cidr`, `allowed_iso3166list`)
4. ✅ Checks rate limits (`max_requests`, `maxrq_window`)
5. ✅ **Validates route permissions** - Checks if requested route exists in token's `permissioned_routes`
6. ✅ Attaches `req.user` object for downstream use

---

## What Makes a Request Unauthorized?

A client request will be **rejected as unauthorized (401)** if:

### 1. **Route Not in Token's Permissions**

**Example:**
```json
// Token has:
{
  "permissioned_routes": {
    "entities": {
      "methods": {
        "/api/timezone": "+0",
        "/api/login": "+0"
      }
    }
  }
}
```

```http
# ✅ ALLOWED
GET /api/timezone
Authorization: Bearer <token>

# ❌ UNAUTHORIZED - route not in token
GET /api/metrics
Authorization: Bearer <token>
```

**Response:**
```json
{
  "error": "Unauthorized",
  "message": "Access to this route is not permitted by your token",
  "statusCode": 401
}
```

### 2. **Token Expired**

```json
{
  "not_after": "2026-10-22"
}
```

If current date > 2026-10-22:
```json
{
  "error": "Unauthorized",
  "message": "Token has expired",
  "statusCode": 401
}
```

### 3. **Token Not Yet Valid**

```json
{
  "not_before": "2025-10-20"
}
```

If current date < 2025-10-20:
```json
{
  "error": "Unauthorized", 
  "message": "Token is not yet valid",
  "statusCode": 401
}
```

### 4. **IP Address Blocked**

```json
{
  "allowed_cidr": "192.168.1.0/24"
}
```

Request from IP `10.0.0.5`:
```json
{
  "error": "Unauthorized",
  "message": "Access from your IP address is not permitted",
  "statusCode": 401
}
```

### 5. **Geographic Restriction**

```json
{
  "allowed_iso3166list": "{\"allow\":[\"US\",\"CA\"]}"
}
```

Request from IP geolocated to Germany (DE):
```json
{
  "error": "Unauthorized",
  "message": "Access from your country is not permitted",
  "statusCode": 401
}
```

### 6. **Rate Limit Exceeded**

```json
{
  "max_requests": "100",
  "maxrq_window": "3600"
}
```

After 100 requests in 1 hour:
```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded",
  "statusCode": 429
}
```

### 7. **Invalid JWT Signature**

Token signature doesn't match or token is malformed:
```json
{
  "error": "Unauthorized",
  "message": "Invalid token signature",
  "statusCode": 401
}
```

### 8. **Missing Authorization Header**

No `Authorization` header provided:
```json
{
  "error": "Unauthorized",
  "message": "No authorization token provided",
  "statusCode": 401
}
```

---

## Admin Authorization (Second Tier)

Some endpoints require **both** `authenticate` AND `authorize`:

```javascript
// From sessionroutes.js line 133
router.get('/list_all', authenticate_apicall, authorize, async (req, res) => {
  // Admin-only endpoint
});
```

**What `authorize` does** (implemented in SDK):
- Checks if user has admin/elevated permissions
- Validates against additional permission flags in token metadata
- May check specific permission levels (e.g., `"+1"` for admin vs `"+0"` for regular)

**Unauthorized for admin endpoints if:**
- Token has route permission but insufficient privilege level
- User doesn't have admin flag in token metadata

---

## Permission Hierarchy

```
Server's Own RODIT Token
  └── Contains: All routes server can grant
      │
      ├── Client Token Request
      │   └── Must be subset of server's routes
      │       │
      │       └── Signed Client Token
      │           └── Contains: Only requested routes (validated subset)
      │               │
      │               └── API Request
      │                   └── Validated against client token's routes
```

### Example Flow:

**Server's RODIT:**
```json
{
  "permissioned_routes": {
    "entities": {
      "methods": {
        "/api/login": "+0",
        "/api/logout": "+0",
        "/api/timezone": "+0",
        "/api/timezone/area": "+0",
        "/api/timezone/time": "+0",
        "/api/ip": "+0",
        "/api/sign/hash": "+0",
        "/api/metrics": "+0"
      }
    }
  }
}
```

**Client Requests:**
```json
{
  "permissioned_routes": {
    "entities": {
      "methods": {
        "/api/timezone": "+0",
        "/api/ip": "+0"
      }
    }
  }
}
```

**✅ Validation Passes** - Client routes are subset of server routes

**Client Token Issued:**
```json
{
  "token_id": "01K86E1DFAYF2RZJZP15J88R00",
  "metadata": {
    "permissioned_routes": "{\"entities\": {\"methods\": {\"/api/timezone\": \"+0\", \"/api/ip\": \"+0\"}}}"
  }
}
```

**Client API Requests:**
- ✅ `GET /api/timezone` - Allowed (in token)
- ✅ `GET /api/ip` - Allowed (in token)
- ❌ `GET /api/metrics` - **Unauthorized** (not in token, even though server has it)
- ❌ `GET /api/logout` - **Unauthorized** (not in token)

---

## Key Security Principles

### 1. **Principle of Least Privilege**
Clients can only request permissions they need, not all server permissions.

### 2. **Whitelist-Based**
Only explicitly granted routes are accessible. No wildcards or pattern matching.

### 3. **Hierarchical Trust**
- Server trusts SignPortal (validates server's token)
- SignPortal trusts server (validates client token requests)
- Client trusts server (uses issued token)
- Server validates client (checks token on each request)

### 4. **Defense in Depth**
Multiple validation layers:
- Route permissions (required for all protected routes)
- Admin authorization (required for admin routes)
- Rate limiting (prevents abuse)
- Network restrictions (CIDR, geo-blocking)
- Temporal validity (not_before, not_after)

### 5. **Immutable Permissions**
Once a token is issued, its permissions cannot be changed. Client must request a new token.

---

## Route Protection Levels

### Level 0: Public (No Auth)
```javascript
app.get("/health", async (req, res) => { ... });
```
- `/health`
- `/api-docs`
- `/swagger.json`

### Level 1: Authenticated (authenticate middleware)
```javascript
app.use("/api", app.locals.roditClient.authenticate);
```
- `/api/timezone`
- `/api/ip`
- `/api/logout`
- `/api/metrics`
- All protected routes

**Requires:**
- Valid JWT token
- Route in token's `permissioned_routes`

### Level 2: Authenticated + Authorized (authenticate + authorize middleware)
```javascript
router.get('/list_all', authenticate_apicall, authorize, async (req, res) => { ... });
```
- `/api/sessions/list_all`
- `/api/sessions/close`

**Requires:**
- Valid JWT token
- Route in token's `permissioned_routes`
- Admin/elevated permission level

### Level 3: Public but Rate-Limited
```javascript
app.use('/api/login', sdkFactory(login.max, login.windowMinutes));
```
- `/api/login`
- `/api/signclient`

**Requires:**
- No auth, but IP-based rate limiting applies

---

## Summary

**Permission Cross-Reference:**
1. Server has master list of routes in its own RODIT token
2. Client requests subset of those routes
3. Server validates request is subset (rejects if not)
4. SignPortal signs client token with validated subset
5. On each API call, SDK validates request route against client token's permissions

**Unauthorized Triggers:**
- Route not in token's `permissioned_routes`
- Token expired or not yet valid
- IP/country restrictions violated
- Rate limit exceeded
- Invalid signature
- Missing authorization header
- Insufficient admin privileges (for admin routes)

**The `METHOD_PERMISSION_MAP` in `config/default.json` is NOT used in this flow.** All permission validation happens through RODIT token metadata.
