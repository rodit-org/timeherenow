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


#### Quick Reference for Frontend Integration

**Base URL**: `https://timeherenow.rodit.org:8443`

**Available Endpoints**:
- `POST /api/login` - Authentication (no auth required)
- `POST /api/logout` - Logout (requires auth)
- `GET /health` - Health check
- `GET /api-docs` - API documentation
- `PUT /api/timezone` - List all IANA timezones
- `PUT /api/timezone/area` - List timezones for a given area
- `PUT /api/timezone/time` - Get current time for a timezone (or by client IP)
- `PUT /api/timezones/by-country` - List timezones by ISO country code
- `PUT /api/ip` - Get current time by IP (IPv4 or IPv6)
- `PUT /api/near-health` - NEAR RPC health check

**Authentication**: Most endpoints require `Authorization: Bearer <JWT_TOKEN>` header obtained from `/api/login`.

**DateTimeJsonResponse**:
```json
{
  "user_ip": "203.0.113.10",
  "date_time": "2025-10-08T10:57:01.123+02:00",
  "day_of_week": 3,
  "day_of_year": 281,
  "dst_trueorfalse": true,
  "dst_offset": 3600,
  "time_zone": "Europe/Berlin",
  "unix_time": 175,
  "utc_datetime": "2025-10-08T08:57:01.123Z",
  "utc_offset": "+02:00",
  "week_number": 41,
  "raw_offset": 3600,
  "locale": "de-DE"
}
```
Fields in bold are the canonical set used by clients: `user_ip`, `date_time`, `day_of_week`, `day_of_year`, `dst_trueorfalse`, `dst_offset`, `time_zone`, `unix_time`, `utc_datetime`, `utc_offset`, `week_number`.
`raw_offset` (seconds) and `locale` are also returned for convenience but are not required.

**IANA Time Zone Database (tzdb)**:
#### Time Endpoints

- **PUT `/api/timezone`**
  - Response: `string[]` of IANA tzdb IDs, e.g., `"Europe/Berlin"`, `"America/Indiana/Knox"`.

- **PUT `/api/timezone/area`**
  - Request:
    ```json
    { "area": "America" }
    ```
  - Response: `string[]` of timezones beginning with `"America/"`.

- **PUT `/api/timezones/by-country`**
  - Request:
    ```json
    { "country_code": "US" }
    ```
  - Response: `string[]` of timezones for the ISO 3166-1 alpha-2 code.

- **PUT `/api/timezone/time`** (preferred) and legacy segmented params
  - Request (preferred):
    ```json
    { "timezone": "Europe/Berlin", "locale": "de-DE" }
    ```
  - Legacy request (supported):
    ```json
    { "area": "America", "location": "Indiana", "region": "Knox", "locale": "en-US" }
    ```
  - Response (DateTimeJsonResponse):
    ```json
    {
      "user_ip": "203.0.113.10",
      "date_time": "2025-10-08T10:57:01.123+02:00",
      "day_of_week": 3,
      "day_of_year": 281,
      "dst_trueorfalse": true,
      "dst_offset": 3600,
      "time_zone": "Europe/Berlin",
      "unix_time": 175, 
      "utc_datetime": "2025-10-08T08:57:01.123Z",
      "utc_offset": "+02:00",
      "week_number": 41,
      "raw_offset": 3600,
      "locale": "de-DE"
    }
    ```
    - Fields in bold are the canonical set used by clients: `user_ip`, `date_time`, `day_of_week`, `day_of_year`, `dst_trueorfalse`, `dst_offset`, `time_zone`, `unix_time`, `utc_datetime`, `utc_offset`, `week_number`.
    - `raw_offset` (seconds) and `locale` are also returned for convenience but are not required.

- **PUT `/api/ip`**
  - Request (optional IP; falls back to client IP):
    ```json
    { "ip": "2001:db8::1", "locale": "en-GB" }
    ```
  - Response: DateTimeJsonResponse (same as above), using timezone resolved from the IP.

- **PUT `/api/near-health`**
  - Response:
    ```json
    { "status": "healthy", "endpoint": "https://rpc.mainnet.near.org", "timestamp": "2025-10-08T10:57:01.000Z" }
    ```

##### Time zone data sourcing
- Time zones are sourced from the IANA Time Zone Database (tzdb). See `api-docs/swagger.json` `externalDocs` referencing IANA.
- This project uses `@vvo/tzdb` to access tzdb data.
- Update tzdb:
  - `npm run update-tzdata` (uses `scripts/update-tzdata.sh`)
  - Check version/count: `npm run tz:version`

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

Not available in this API build.

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
    "timezone": ["entityAndProperties", "entityOnly"],
    "timezone.txt": ["entityAndProperties", "entityOnly"],
    "ip": ["entityAndProperties", "entityOnly"],
    "ip.txt": ["entityAndProperties", "entityOnly"],
    "near-health": ["entityAndProperties"],
    "logout": ["entityAndProperties"]
  }
}
```

- **timezone**/**timezone.txt**: List timezones and access area-specific listings
- **ip**/**ip.txt**: Get current time based on client/specified IP
- **near-health**: NEAR RPC health check endpoint
- **logout**: Session termination

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
