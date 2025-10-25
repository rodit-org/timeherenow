# METHOD_PERMISSION_MAP Generator

This script automatically generates the `METHOD_PERMISSION_MAP` configuration from the OpenAPI/Swagger specification (`api-docs/swagger.json`).

## Purpose

The `METHOD_PERMISSION_MAP` defines which permission scopes are allowed for each API operation. Previously, this was manually maintained in `config/default.json`, which could lead to:
- Inconsistencies between API documentation and permission configuration
- Forgotten updates when adding new endpoints
- Duplication of API structure information

This script solves these problems by treating `swagger.json` as the single source of truth.

## Usage

### Generate and Update Config (Default)

```bash
node scripts/generate-permission-map.js
```

This will:
1. Read `api-docs/swagger.json`
2. Generate the permission map from authenticated endpoints
3. Update `config/default.json` with the new map

### Validate Without Updating

```bash
node scripts/generate-permission-map.js --validate
```

This will:
1. Generate the permission map
2. Compare it with the existing config
3. Report any differences
4. Exit with code 0 if valid, 1 if differences found

### Custom Output Path

```bash
node scripts/generate-permission-map.js --output path/to/config.json
```

## How It Works

### 1. Operation Name Extraction

The script extracts operation names from API paths by taking the last path segment:

- `/login` → `login`
- `/timezone/area` → `area`
- `/timezone/time` → `time`
- `/sessions/list_all` → `list_all`

### 2. Authentication Detection

Only endpoints that require authentication are included. The script checks for the `security` field in the OpenAPI specification:

```json
{
  "paths": {
    "/timezone": {
      "post": {
        "security": [{ "bearerAuth": [] }],  // ← Requires auth
        ...
      }
    }
  }
}
```

Unauthenticated endpoints like `/login`, `/signclient`, and `/health` are automatically skipped.

### 3. Default Permission Scopes

By default, all operations allow all three permission scopes:
- `entityAndProperties` - Full access (prefix: `+`)
- `propertiesOnly` - Properties only (prefix: `-`)
- `entityOnly` - Entity only (no prefix)

### 4. Custom Permission Scopes (Optional)

You can customize permission scopes for specific operations using the `x-permission-scopes` extension in `swagger.json`:

```json
{
  "paths": {
    "/admin/endpoint": {
      "post": {
        "summary": "Admin only endpoint",
        "x-permission-scopes": ["entityAndProperties"],
        "security": [{ "bearerAuth": [] }],
        ...
      }
    }
  }
}
```

This would restrict the `/admin/endpoint` operation to only allow `entityAndProperties` scope.

## Integration with CI/CD

The script runs automatically during GitHub Actions deployment:

```yaml
- name: Generate METHOD_PERMISSION_MAP from swagger.json
  run: |
    echo "Generating METHOD_PERMISSION_MAP from swagger.json..."
    node scripts/generate-permission-map.js
    
    echo "Validating generated permission map..."
    node scripts/generate-permission-map.js --validate || echo "⚠️ Validation warnings detected (non-blocking)"
    
    echo "✓ Permission map generation complete"
```

This ensures that:
1. The permission map is always up-to-date with the API specification
2. Any inconsistencies are detected during deployment
3. The deployed application has the correct permissions

## Output Example

```
=== METHOD_PERMISSION_MAP Generator ===

✓ Loaded swagger.json from /path/to/api-docs/swagger.json

Generating METHOD_PERMISSION_MAP from swagger.json...

ℹ️  Skipping unauthenticated endpoint: /login (login)
✓ logout               <- /logout
✓ timezone             <- /timezone
✓ area                 <- /timezone/area
✓ time                 <- /timezone/time
✓ by-country           <- /timezones/by-country
✓ ip                   <- /ip
✓ hash                 <- /sign/hash
✓ schedule             <- /timers/schedule
✓ resources            <- /mcp/resources
✓ metrics              <- /metrics
✓ system               <- /metrics/system
✓ list_all             <- /sessions/list_all
✓ revoke               <- /sessions/revoke
✓ cleanup              <- /sessions/cleanup

✓ Generated 14 permission entries

Updating /path/to/config/default.json...
✓ Config file updated successfully!
```

## Validation Report

When running with `--validate`, the script provides a detailed report:

```
=== Validation Report ===

❌ Operations in config but NOT in swagger.json:
   - deprecated_endpoint: ["entityAndProperties","propertiesOnly","entityOnly"]

ℹ️  New operations found in swagger.json:
   + new_endpoint: ["entityAndProperties","propertiesOnly","entityOnly"]

✓ Existing operations match, but there are new operations to add.
```

## Troubleshooting

### Duplicate Operation Names

If multiple paths end with the same segment, you'll see a warning:

```
⚠️  Duplicate operation name detected: time
    Existing: ["entityAndProperties","propertiesOnly","entityOnly"]
    New from /another/path/time: ["entityAndProperties","propertiesOnly","entityOnly"]
    Keeping existing definition.
```

**Solution**: Ensure unique operation names by using different path structures or adding unique segments.

### Missing Operations

If the validation shows operations in config but not in swagger:

```
❌ Operations in config but NOT in swagger.json:
   - old_endpoint: [...]
```

**Possible causes**:
1. The endpoint was removed from the API but not from config (safe to remove)
2. The endpoint exists but isn't documented in swagger.json (add it to swagger)
3. The endpoint is unauthenticated and was incorrectly in the permission map (safe to remove)

## Maintenance

### When to Run Manually

You should run this script manually when:
1. Adding new authenticated endpoints to `swagger.json`
2. Removing endpoints from the API
3. Changing authentication requirements for endpoints
4. Customizing permission scopes for specific operations

### When It Runs Automatically

The script runs automatically:
1. During every GitHub Actions deployment
2. Before the application is deployed to production

This ensures the deployed application always has the correct permission configuration.

## Related Files

- **Script**: `scripts/generate-permission-map.js`
- **Input**: `api-docs/swagger.json` (OpenAPI specification)
- **Output**: `config/default.json` (METHOD_PERMISSION_MAP)
- **Validator**: `sdk/lib/middleware/validatepermissions.js` (uses the map)
- **CI/CD**: `.github/workflows/deploy.yml` (runs the script)
