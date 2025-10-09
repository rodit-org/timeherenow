#### Quick Reference for Frontend Integration

**Base URL**: `https://timeherenow.rodit.org`


**Available Endpoints**:
- `POST /api/login` - Authentication
- `POST /api/logout` - Logout
- `GET /health` - Health check
- `GET /api-docs` - API documentation
- `PUT /api/timezone` - List all IANA timezones
- `PUT /api/timezone/area` - List timezones for a given area
- `PUT /api/timezone/time` - Get current time for a timezone (or by client IP)
- `PUT /api/timezones/by-country` - List timezones by ISO country code
- `PUT /api/ip` - Get current time with location obtained from theIP (IPv4 or IPv6)


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
  "locale": "de-DE",
  "likely_time_difference_ms": 850
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
    - `likely_time_difference_ms` is a conservative (>99% likely) upper bound on the difference between real time and the returned time, given 5 Hz polling and ~0.6 s block time.
  - Errors: returns HTTP 503 if NEAR blockchain time is unavailable.

- **PUT `/api/ip`**
  - Request (optional IP; falls back to client IP):
    ```json
    { "ip": "2001:db8::1", "locale": "en-GB" }
    ```
  - Response: DateTimeJsonResponse (same as above), using timezone resolved from the IP.
  - Errors: returns HTTP 503 if NEAR blockchain time is unavailable.

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

##### NEAR time polling and availability
- The API polls NEAR blockchain time at 5 Hz and serves the most recent cached value to reduce latency and RPC load.
- If NEAR time is unavailable (no cached value), time endpoints return HTTP 503.
- Tuning environment variables:
  - `NEAR_POLL_MS` (default `200`): polling interval in ms
  - `NEAR_BLOCK_MS` (default `600`): expected block interval in ms
  - `NEAR_NET_MARGIN_MS` (default `50`): network jitter margin in ms

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
Session termination endpoint.

**Headers**: `Authorization: Bearer <JWT_TOKEN>`

#### Signing Endpoints

Not available in this API build.

#### System Endpoints

##### GET /health
Health check endpoint for monitoring server status with embedded NEAR RPC status.

**Response (200)**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "service": "Time Here Now API",
  "near": {
    "status": "healthy",
    "endpoint": "https://rpc.mainnet.near.org",
    "timestamp": "2025-10-08T10:57:01.000Z",
    "cache_available": true,
    "last_fetch_timestamp": "2025-10-08T10:57:00.950Z",
    "last_fetch_age_ms": 50,
    "last_block_timestamp": "2025-10-08T10:57:00.400Z",
    "last_block_age_ms": 600,
    "poll_interval_ms": 200,
    "block_interval_ms": 600,
    "network_margin_ms": 50,
    "likely_time_difference_ms": 850
  }
}
```

##### GET /api-docs
Interactive Swagger UI documentation for the API.

The `token_id` fields contain unique identifiers generated by the facial combination generator.

### API Documentation
Complete OpenAPI 3.0.3 specification available at: `api-docs/swagger.json`

**Live Documentation**: Available at `https://timeherenow.rodit.org/api-docs/`

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
    "logout": ["entityAndProperties"]
  }
}
```

- **timezone**/**timezone.txt**: List timezones and access area-specific listings
- **ip**/**ip.txt**: Get current time based on client/specified IP
- **logout**: Session termination

These permissions are validated against the RODIT token's `permissioned_routes` field during API calls.

### Docker Configuration

#### api.Dockerfile - API Container
- **Base Image**: `node:20-alpine` for lightweight Node.js runtime
- **Security**: Runs as non-root user `nodeuser`
- **Process Manager**: Uses `tini` for proper signal handling
- **Entry Point**: Starts the API server via `src/app.js`

#### nginx/nginx.Dockerfile - Reverse Proxy Container
- **Base Image**: `nginx:mainline-alpine` for latest nginx features
- **Configuration**: Uses custom `nginx/nginx.conf`
- **Security**: Runs as nginx user with restricted permissions

### Nginx Configuration (nginx/nginx.conf)

The nginx reverse proxy provides:

**SSL/TLS Security**:
- TLS 1.2/1.3 protocols only
- Strong cipher suites (ECDHE-based)
- Security headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection)

**CORS Configuration**:
- Enabled only for `POST /api/signclient` and only for origin `https://purchase.timeherenow.com`
- Preflight `OPTIONS` handled at the proxy
- Credentials supported for that endpoint

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
