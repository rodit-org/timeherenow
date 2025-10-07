![cableguard logo banner](./banner.png)

## SIGN RODIT API signing RODiT ID
SIGN API signs Root and Client RODiT.

## 0. Pre requisites
- near cli installed
- Download the code from the repository
- When downloading from VS Code it is possible that the shell script files have the wrong permissions and need to be set x so they can run
- Installing npm
- node -v
- sudo npm cache clean -f
- sudo npm install -g n
- sudo n stable
- node -v

## 1. Install and Build
- npm install (in each directory)
- npm run build

## 2. Create the signing key pair
- Install near-cli-rs
- Use near-cli-rs to create a NEAR implicit account ID and a key pair with the command: near generate-key

Output example:
- Key pair with ed25519:BNcExLS7k84HswwFHpB49jZnh1y6bsRS7P51FVmeBBxs public key for an ACCOUNT "9a1de9b4aa4ddd4a3091f43f1de680a9f5405d70e8ca69c3fb5daa96b5cd1270"
- Resulting in the key pair stored in: ~/.near-credentials/testnet/9a1de9b4aa4ddd4a3091f43f1de680a9f5405d70e8ca69c3fb5daa96b5cd1270.json
- From your NEAR wallet send some 0.01 Near to the newly generated implicit account ID to activate it
- Store the account in a secret store. This implementation uses Hashicorp Vault.

## 3. Build
- npm run build

## 4. Run
- sudo NODE_ENV=development node app.js
- Start the Front End as a background process: setsid npm run start >/dev/null 2>&1 < /dev/null &

## 5. API Components

### Facial Combination Generator
The API uses a unique identifier generation system based on facial feature combinations located at `src/utils/facialCombinationGenerator.js`.

**Purpose**: Generates cryptographically-sound unique identifiers for RODIT tokens using encoded facial feature combinations with Spanish NIF checksum validation.

**Key Features**:
- Generates over 2 billion unique combinations from 11 facial feature categories
- Encodes combinations into compact 22-character strings with built-in checksums
- Uses Spanish NIF validation algorithm for data integrity
- Originally designed for AI image generation prompts, repurposed for secure ID generation

**Usage in API**:
- **RODIT Token IDs**: Each signed RODIT token gets a unique identifier (`token_id` field)
- **Request Tracking**: Generates unique request IDs for logging and debugging
- **Session Management**: Creates traceable identifiers for API operations

### API Endpoints

#### Quick Reference for Frontend Integration

**Base URL**: `https://timeherenow.rodit.org:8443`

**Available Endpoints**:
- `POST /login` - Authentication (no auth required)
- `POST /logout` - Logout (requires auth)
- `POST /api/timeherenow/timeherenow` - Sign timeherenow tokens (requires auth)
- `POST /api/root/signroot` - Sign root tokens (no auth required)
- `GET /health` - Health check
- `GET /api-docs` - API documentation

**Authentication**: Most endpoints require `Authorization: Bearer <JWT_TOKEN>` header obtained from `/login`.

---

#### Authentication Endpoints

##### POST /login
RODiT mutual authentication endpoint for obtaining session tokens.

**Request Body**:
```json
{
  "roditToken": "string"
}
```

**Response (200)**:
```json
{
  "success": true,
  "message": "Authentication successful",
  "user": {
    "id": "string"
  },
  "token": "string"
}
```

##### POST /logout
Session termination endpoint (requires authentication).

**Headers**: `Authorization: Bearer <JWT_TOKEN>`

#### Signing Endpoints

##### POST /api/timeherenow/timeherenow
Generates and signs client RODIT tokens for timeherenow operations.

**Headers**: `Authorization: Bearer <JWT_TOKEN>`

**Request Body**:
```json
{
  "tamperproofedValues": {
    "serviceprovider_id": "string",
    "openapijson_url": "string (URI format)", 
    "not_after": "string (ISO date-time)",
    "not_before": "string (ISO date-time)",
    "max_requests": "integer",
    "maxrq_window": "integer",
    "webhook_cidr": "string",
    "allowed_cidr": "string",
    "allowed_iso3166list": "array of strings",
    "jwt_duration": "string",
    "permissioned_routes": "array of strings",
    "subjectuniqueidentifier_url": "string (URI format)"
  },
  "mintingfee": "number",
  "mintingfeeaccount": "string"
}
```

**Response (200)**:
```json
{
  "token_id": "ALBFCHDBEDFDGBHEIBJAKEV",
  "serviceprovider_public_key_base64url": "string",
  "serviceprovider_signature": "string", 
  "fee_signature_base64url": "string",
  "requestId": "string",
  "...tamperproofedValues"
}
```

##### POST /api/root/signroot
Generates and signs RODiT tokens for root operations (more complex dual-token system).

**Request Body**:
```json
{
  "SharedValues": {
    "openapijson_url": "string (URI format)",
    "not_after": "string (ISO date-time)",
    "not_before": "string (ISO date-time)",
    "max_requests": "integer",
    "maxrq_window": "integer",
    "webhook_cidr": "string",
    "allowed_cidr": "string",
    "allowed_iso3166list": "array of strings",
    "jwt_duration": "string",
    "permissioned_routes": "array of strings",
    "subjectuniqueidentifier_url": "string (URI format)"
  },
  "mintingfee": "number",
  "mintingfeeaccount": "string"
}
```

**Response (200)**:
```json
{
  "timeherenow_token_id": "string",
  "sanctum_token_id": "string", 
  "combined_id_timeherenow": "string",
  "combined_id_sanctum": "string",
  "serviceprovider_signature": "string",
  "serviceprovider_public_key_base64url": "string",
  "sanctum_fee_signature_base64url": "string"
}
```

**Error Responses (400/401/500)**:
```json
{
  "error": "string",
  "message": "string", 
  "requestId": "string"
}
```

#### System Endpoints

##### GET /health
Health check endpoint for monitoring server status.

**Response (200)**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

##### GET /api-docs
Interactive Swagger UI documentation for the API.

The `token_id` fields contain unique identifiers generated by the facial combination generator.

### API Documentation
Complete OpenAPI 3.0.3 specification available at: `api-docs/swagger.json`

**Live Documentation**: Available at `https://timeherenow.rodit.org:8443/api-docs/`

## 6. Configuration and Deployment

### Configuration Files

#### config/default.json - Permission Configuration
The `METHOD_PERMISSION_MAP` defines which API methods require specific permissions:

```json
{
  "METHOD_PERMISSION_MAP": {
    "timeherenow": ["entityAndProperties"],
    "signroot": ["entityAndProperties"]
  }
}
```

- **timeherenow**: Requires `entityAndProperties` permission for client RODIT token signing (`/api/timeherenow/timeherenow`)
- **signroot**: Requires `entityAndProperties` permission for root RODIT token signing (`/api/root/signroot`)

These permissions are validated against the RODIT token's `permissioned_routes` field during API calls.

### Docker Configuration

#### api.Dockerfile - API Container
- **Base Image**: `node:18-alpine` for lightweight Node.js runtime
- **Security**: Runs as non-root user `nodeuser`
- **Process Manager**: Uses `tini` for proper signal handling
- **Port**: Exposes port 8080 for API access
- **Entry Point**: Starts the API server via `src/app.js`

#### nginx/nginx.Dockerfile - Reverse Proxy Container
- **Base Image**: `nginx:mainline-alpine` for latest nginx features
- **SSL/TLS**: Configured for HTTPS on port 8443
- **Configuration**: Uses custom `nginx/nginx.conf`
- **Security**: Runs as nginx user with restricted permissions

### Nginx Configuration (nginx/nginx.conf)

The nginx reverse proxy provides:

**SSL/TLS Security**:
- TLS 1.2/1.3 protocols only
- Strong cipher suites (ECDHE-based)
- Security headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection)

**CORS Configuration**:
- Whitelist of allowed origins for cross-origin requests
- Supports preflight OPTIONS requests
- Credentials support for authenticated requests

**Allowed Origins**:
- `https://mainnet.rodit.org:6443`
- `https://mainnet.rodit.org:2443`
- `https://server.discernible.io:2443`
- `https://purchase.discernible.io:4443`
- `https://timeherenow.rodit.org:8443`

**Proxy Features**:
- WebSocket support for real-time connections
- Request/response logging with detailed format
- Error handling with CORS-compliant responses
- Timeouts: 60s for connect/send/read operations

### Logging Configuration (promtail/promtail-config.yml)

Promtail collects and forwards logs to Grafana Loki:

**Configuration**:
- **Target**: `https://grafana.cableguard.net:3100/loki/api/v1/push`
- **TLS**: Insecure skip verify enabled for internal networks
- **Retry Logic**: Exponential backoff (500ms to 5m, max 10 retries)

**Log Collection**:
- **Path**: `/app/logs/*.log`
- **Labels**: 
  - `job: timeherenow-api`
  - `hostname: timeherenow.rodit.org`
  - `app: timeherenow-api`

**Log Processing**:
- Filename extraction for log categorization
- Component detection (api/nginx/system)
- Log type classification (error/access/info)
- Filtering to reduce noise (drops webhook startup messages)

### GitHub Actions Deployment (.github/workflows/deploy.yml)

**Trigger Events**:
- Push to `20250705mcp` branch
- Pull requests to `20250705mcp` branch
- Manual workflow dispatch with commit SHA selection

**Deployment Process**:

1. **Setup Phase**:
   - Checkout specified commit
   - Setup Node.js 18 with npm cache
   - Install dependencies

2. **File Transfer**:
   - SSH key installation for secure access
   - Directory creation on target server (`~/timeherenow-app/`)
   - Rsync file transfer (excludes .git, node_modules, logs, data)

3. **Container Deployment**:
   - **Cleanup**: Remove existing pods and images
   - **Pod Creation**: Create `timeherenow-pod` with port 8443 exposed
   - **API Container**: Build and run from `api.Dockerfile`
   - **Nginx Container**: Build and run from `nginx/nginx.Dockerfile`
   - **Promtail Container**: Run from official Grafana image

4. **Environment Variables**:
   - Loki logging configuration
   - RODIT/NEAR blockchain settings
   - HashiCorp Vault authentication
   - Service identification and ports

**Target Environment**:
- **Server**: `174.138.10.2`
- **Domain**: `timeherenow.rodit.org`
- **Port**: `8443` (HTTPS)
- **Container Runtime**: Podman

**Volume Mounts**:
- `/app/logs`: Application logs (shared with Promtail)
- `/app/data`: Persistent application data
- `/app/certs`: SSL certificates (read-only)

### Security Considerations

1. **Container Security**: Non-root users in all containers
2. **Network Security**: HTTPS-only with strong TLS configuration
3. **CORS Security**: Strict origin whitelist
4. **Secrets Management**: HashiCorp Vault integration
5. **Log Security**: Secure log forwarding to centralized system
