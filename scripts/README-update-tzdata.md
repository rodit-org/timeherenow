# IANA Time Zone Database Update Script

## Overview

The `update-tzdata.sh` script updates the IANA Time Zone Database (tzdb) by upgrading the `@vvo/tzdb` npm package. This ensures the API has the latest timezone definitions, including new timezones, renamed zones, and updated DST rules.

## Why This Matters

The Time Here Now API relies on accurate timezone data from the IANA Time Zone Database. This database is updated several times per year to reflect:

- **New timezones**: Countries or regions adopting new timezone rules
- **DST changes**: Updates to daylight saving time start/end dates
- **Political changes**: Timezone boundary adjustments
- **Historical corrections**: Fixes to past timezone data
- **Renamed zones**: Deprecated zone names and their replacements

Without regular updates, the API could return incorrect times for affected regions.

## Usage

### Manual Update (Local Development)

```bash
# Update to latest version
bash scripts/update-tzdata.sh

# Update to specific version
bash scripts/update-tzdata.sh 6.186.0
```

The script will:
1. Show current `@vvo/tzdb` version and timezone count
2. Install the requested version
3. Show updated version and timezone count
4. Remind you to commit `package.json` and `package-lock.json`

### Automated Update (GitHub Actions)

The script is integrated into the deployment workflow and can be triggered via manual workflow dispatch:

1. Go to **Actions** tab in GitHub
2. Select **Deploy Node.js API** workflow
3. Click **Run workflow**
4. Check the **"Update IANA Time Zone Database"** option
5. Enter commit SHA (or leave default)
6. Click **Run workflow**

The deployment will:
1. Update `@vvo/tzdb` to the latest version
2. Generate the permission map
3. Deploy with the updated timezone data

**Important**: After deployment with tzdata update, you should:
1. Pull the updated `package.json` and `package-lock.json`
2. Commit them to lock the update
3. Push to the repository

## Script Details

### What It Does

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Detect current version and timezone count
CURRENT_TZDB_PKG=$(node -e "console.log(require('@vvo/tzdb/package.json').version)")
CURRENT_TZ_COUNT=$(node -e "const {getTimeZones}=require('@vvo/tzdb');console.log(getTimeZones().length)")

# 2. Install requested version (default: latest)
npm install "@vvo/tzdb@${TZDB_VERSION}" --save

# 3. Show updated version and timezone count
UPDATED_TZDB_PKG=$(node -e "console.log(require('@vvo/tzdb/package.json').version)")
UPDATED_TZ_COUNT=$(node -e "const {getTimeZones}=require('@vvo/tzdb');console.log(getTimeZones().length)")
```

### Output Example

```
[tzdb] Project root: /home/user/timeherenow-rodit
[tzdb] Requested @vvo/tzdb version: latest
[tzdb] Node: v20.11.0
[tzdb] npm:  10.2.4
[tzdb] Current @vvo/tzdb: 6.185.0
[tzdb] Current zones count: 424
[tzdb] Installing @vvo/tzdb@latest ...
[tzdb] Reading updated versions ...
[tzdb] Updated @vvo/tzdb: 6.186.0
[tzdb] Updated zones count: 425
[tzdb] Done. Commit package.json and package-lock.json to lock the update.
```

## Integration with Deployment

### Workflow Configuration

In `.github/workflows/deploy.yml`:

```yaml
workflow_dispatch:
  inputs:
    update_tzdata:
      description: 'Update IANA Time Zone Database (@vvo/tzdb) to latest version'
      required: false
      type: boolean
      default: false
```

### Deployment Step

```yaml
- name: Update IANA Time Zone Database
  if: ${{ github.event.inputs.update_tzdata == 'true' }}
  run: |
    echo "Updating IANA Time Zone Database (@vvo/tzdb) to latest version..."
    bash scripts/update-tzdata.sh
    
    echo "✓ Time zone database update complete"
    echo "⚠️  Remember to commit package.json and package-lock.json if this is a manual update"
```

The step only runs when explicitly requested via workflow dispatch input.

## When to Update

### Regular Schedule

Consider updating the timezone database:

- **Quarterly**: IANA typically releases updates 4-6 times per year
- **Before major holidays**: DST changes often occur around spring/fall
- **After political changes**: When countries announce timezone policy changes

### Monitoring for Updates

Check for new releases:

1. **IANA tzdb releases**: https://www.iana.org/time-zones
2. **@vvo/tzdb releases**: https://github.com/vvo/tzdb/releases
3. **npm package**: https://www.npmjs.com/package/@vvo/tzdb

### Urgent Updates

Update immediately when:

- A country announces an emergency timezone change
- Critical bug fixes are released
- Your API is returning incorrect times for a specific region

## Testing After Update

After updating the timezone database, verify:

1. **Timezone count**: Should match or exceed previous count
2. **API functionality**: Test key endpoints
3. **Specific regions**: Test any recently changed timezones

```bash
# Test timezone listing
curl -X POST https://api.timeherenow.com/api/timezone \
  -H "Authorization: Bearer $TOKEN"

# Test specific timezone
curl -X POST https://api.timeherenow.com/api/timezone/time \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"timezone": "Europe/Berlin"}'

# Test IP-based timezone detection
curl -X POST https://api.timeherenow.com/api/ip \
  -H "Authorization: Bearer $TOKEN"
```

## Rollback

If an update causes issues:

1. **Revert package files**:
   ```bash
   git checkout HEAD~1 -- package.json package-lock.json
   npm install
   ```

2. **Install specific version**:
   ```bash
   bash scripts/update-tzdata.sh 6.185.0  # Previous working version
   git add package.json package-lock.json
   git commit -m "Rollback tzdb to 6.185.0"
   ```

3. **Redeploy**:
   ```bash
   git push origin main
   ```

## Package Information

### @vvo/tzdb

- **Repository**: https://github.com/vvo/tzdb
- **npm**: https://www.npmjs.com/package/@vvo/tzdb
- **License**: MIT
- **Description**: Timezone lookup and information library based on IANA tzdb

### Features Used

The API uses `@vvo/tzdb` for:

- `getTimeZones()`: Get all available timezones
- Timezone metadata: Country codes, coordinates, DST info
- Timezone name validation
- Timezone abbreviation lookup

### Current Usage

In `src/lib/timezone-service.js`:

```javascript
const { getTimeZones } = require('@vvo/tzdb');

// Get all timezones
const timezones = getTimeZones();

// Filter by country
const usTimezones = timezones.filter(tz => 
  tz.countryCode === 'US'
);
```

## Troubleshooting

### Update Fails

```
Error: Cannot find module '@vvo/tzdb'
```

**Solution**: Ensure you're in the project root and `node_modules` exists:
```bash
cd /path/to/timeherenow-rodit
npm install
bash scripts/update-tzdata.sh
```

### Version Conflict

```
npm ERR! peer dependency conflict
```

**Solution**: Check Node.js version compatibility:
```bash
node -v  # Should be v20.x
npm install --legacy-peer-deps "@vvo/tzdb@latest"
```

### Timezone Count Decreased

If the updated timezone count is lower than before:

1. Check the release notes for deprecated timezones
2. Verify the package installed correctly
3. Check for breaking changes in the new version

### Deployment Update Not Persisted

If the update doesn't persist after deployment:

**Cause**: Updated `package.json` and `package-lock.json` were not committed.

**Solution**:
1. After deployment with tzdata update, pull the changes
2. Commit the updated package files
3. Push to repository

## Best Practices

1. **Test locally first**: Run the update script locally before deploying
2. **Review release notes**: Check what changed in the new version
3. **Commit immediately**: Lock the update by committing package files
4. **Document updates**: Note the version and reason in commit messages
5. **Monitor after deployment**: Watch for timezone-related errors

## Related Files

| File | Purpose |
|------|---------|
| `scripts/update-tzdata.sh` | Update script |
| `src/lib/timezone-service.js` | Uses `@vvo/tzdb` |
| `package.json` | Declares `@vvo/tzdb` dependency |
| `package-lock.json` | Locks exact version |
| `.github/workflows/deploy.yml` | CI/CD integration |

## External Resources

- **IANA Time Zone Database**: https://www.iana.org/time-zones
- **tzdb Announcements**: https://mm.icann.org/pipermail/tz-announce/
- **@vvo/tzdb GitHub**: https://github.com/vvo/tzdb
- **Timezone Changes News**: https://www.timeanddate.com/news/time/

## Example Workflow

### Quarterly Update Process

```bash
# 1. Check for new releases
npm view @vvo/tzdb versions --json | tail -n 5

# 2. Update locally
bash scripts/update-tzdata.sh

# 3. Test the API
npm start
# Run manual tests...

# 4. Commit the update
git add package.json package-lock.json
git commit -m "Update @vvo/tzdb to latest IANA tzdb release"
git push origin main

# 5. Deploy automatically via push
# Or manually via GitHub Actions with tzdata update option
```

This ensures your Time Here Now API always has the most accurate and up-to-date timezone information! 🌍⏰
