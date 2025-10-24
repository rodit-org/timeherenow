# Rate Limiting Temporarily Disabled

## Changes Made

Rate limiting has been **temporarily disabled** for testing purposes in `src/app.js`.

### Disabled Components

1. **IP-based rate limiting** for unauthenticated endpoints (`/api/login`, `/api/signclient`)
   - Lines 123-156 in `src/app.js`
   - Previously limited login attempts and signclient requests

2. **User-based rate limiting** for authenticated endpoints
   - Lines 262-276 in `src/app.js`
   - Previously limited authenticated API requests per user

### Code Changes

Both rate limiting sections are now commented out with `/* DISABLED ... */` blocks and early returns.

The function `applyRateLimitersIfAvailable()` now:
- Logs "Rate limiting temporarily disabled"
- Returns immediately without applying any rate limiters

## Swagger Documentation

**No updates needed** to `api-docs/swagger.json` because:
- The Swagger spec does not document rate limiting behavior
- Rate limits are typically communicated via HTTP headers (`X-RateLimit-*`) rather than in the API spec
- The only "limit" references in Swagger are for pagination parameters (e.g., MCP resources limit)

## Impact

### Positive (for testing)
- ✅ Tests can make unlimited requests without hitting rate limits
- ✅ Concurrent session tests won't fail due to rate limiting
- ✅ Load testing and performance testing can run without artificial throttling

### Negative (security/production concerns)
- ⚠️ No protection against brute force login attempts
- ⚠️ No protection against API abuse
- ⚠️ Server could be overwhelmed by excessive requests

## Re-enabling Rate Limiting

To re-enable rate limiting, simply:

1. **Remove the early return and comment blocks:**

```javascript
function applyRateLimitersIfAvailable() {
  if (rateLimitersApplied) {
    return;
  }

  // Remove these lines:
  // logger.info("Rate limiting temporarily disabled", {
  //   component: "TimeHereNowAPI"
  // });
  // rateLimitersApplied = true;
  // return;

  // Uncomment the rest of the function
  const sdkFactory = app.locals?.roditClient?.getRateLimitMiddleware?.();
  // ... rest of the code
}
```

2. **Uncomment the user-based rate limiting section** (lines 262-276)

3. **Restart the server**

## Testing Recommendations

While rate limiting is disabled:
1. ✅ Run all test suites to verify functionality
2. ✅ Test concurrent sessions
3. ✅ Test multiple rapid login attempts
4. ⚠️ **Do NOT deploy to production** with rate limiting disabled
5. ⚠️ Re-enable rate limiting before any production deployment

## Current Rate Limit Settings

When re-enabled, the following limits will apply:

```javascript
const RATE_LIMIT_SETTINGS = {
  global: { max: 240, windowMinutes: 1 },      // 240 requests per minute (authenticated)
  login: { max: 20, windowMinutes: 1 },        // 20 login attempts per minute
  signclient: { max: 6, windowMinutes: 1 }     // 6 signclient requests per minute
};
```

## Files Modified

- `src/app.js` - Rate limiting functions commented out

## Files NOT Modified

- `api-docs/swagger.json` - No changes needed (doesn't document rate limits)
