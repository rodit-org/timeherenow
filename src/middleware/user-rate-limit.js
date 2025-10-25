// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// User-based rate limiting middleware using RODiT metadata

const { logger } = require('@rodit/rodit-auth-be');

/**
 * Creates a user-based rate limiting middleware that uses rate limits from RODiT user metadata.
 * Requires authenticated users with proper rate limit configuration.
 * 
 * @param {Object} roditClient - The RODiT client instance
 * @returns {Function} Express middleware function
 */
function createUserRateLimitMiddleware(roditClient) {
  const getRateLimitFactory = roditClient?.getRateLimitMiddleware?.();
  
  if (typeof getRateLimitFactory !== 'function') {
    throw new Error('Rate limit middleware factory not available from SDK');
  }

  // Cache for user-specific limiters (keyed by user ID)
  const userLimiters = new Map();

  return async (req, res, next) => {
    // Require authenticated user
    if (!req.user || !req.user.id) {
      logger.errorWithContext('User authentication required for rate limiting', {
        component: 'UserRateLimit',
        ip: req.ip,
        path: req.originalUrl
      });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userId = req.user.id;

    try {
      // Check if we have a cached limiter for this user
      if (!userLimiters.has(userId)) {
        // Fetch user's rate limit configuration from RODiT metadata
        const configObject = await roditClient.getConfigOwnRodit();
        const metadata = configObject?.own_rodit?.metadata;

        if (!metadata?.max_requests || !metadata?.maxrq_window) {
          throw new Error('User metadata missing required rate limit configuration');
        }

        const maxRequests = parseInt(metadata.max_requests, 10);
        const windowSeconds = parseInt(metadata.maxrq_window, 10);
        const windowMinutes = windowSeconds / 60;

        logger.info('Creating user-specific rate limiter', {
          component: 'UserRateLimit',
          userId,
          maxRequests,
          windowMinutes,
          windowSeconds
        });

        // Create user-specific rate limiter
        const userLimiter = getRateLimitFactory(maxRequests, windowMinutes);
        userLimiters.set(userId, {
          limiter: userLimiter,
          maxRequests,
          windowMinutes,
          createdAt: Date.now()
        });
      }

      // Get the user's rate limiter
      const userLimiterData = userLimiters.get(userId);
      
      logger.debugWithContext('Applying user-based rate limiting', {
        component: 'UserRateLimit',
        userId,
        maxRequests: userLimiterData.maxRequests,
        windowMinutes: userLimiterData.windowMinutes,
        path: req.originalUrl
      });

      // Apply the user's rate limiter
      return userLimiterData.limiter(req, res, next);

    } catch (error) {
      logger.errorWithContext('Error applying user-based rate limiting', {
        component: 'UserRateLimit',
        userId,
        error: error.message,
        path: req.originalUrl
      }, error);
      
      return res.status(500).json({ error: 'Rate limiting configuration error' });
    }
  };
}

/**
 * Cleanup function to remove old cached limiters
 * Call this periodically to prevent memory leaks
 * 
 * @param {Map} userLimiters - The user limiters cache
 * @param {number} maxAgeMs - Maximum age in milliseconds (default: 1 hour)
 */
function cleanupUserLimiters(userLimiters, maxAgeMs = 60 * 60 * 1000) {
  const now = Date.now();
  let removed = 0;
  
  for (const [userId, data] of userLimiters.entries()) {
    if (now - data.createdAt > maxAgeMs) {
      userLimiters.delete(userId);
      removed++;
    }
  }
  
  if (removed > 0) {
    logger.info('Cleaned up old user rate limiters', {
      component: 'UserRateLimit',
      removed,
      remaining: userLimiters.size
    });
  }
}

module.exports = {
  createUserRateLimitMiddleware,
  cleanupUserLimiters
};
