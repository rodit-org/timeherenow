const express = require('express');
const router = express.Router();
const { ulid } = require('ulid');
const { logger } = require('@rodit/rodit-auth-be');
const TimeZoneService = require('../lib/timezone-service');

// Initialize timezone service for blockchain time
const timezoneService = new TimeZoneService();

router.use(express.json());

function getSessionKey(req) {
  // Access the session manager from roditClient
  const sessionManager = req.app?.locals?.roditClient?.getSessionManager?.();
  if (sessionManager && req.user?.id) {
    // Get active sessions for this user and use the first one
    const sessions = sessionManager.getSessionsByUserId(req.user.id);
    if (sessions && sessions.length > 0) {
      return sessions[0].id || sessions[0].sessionId || sessions[0].sid;
    }
  }
  return req.user?.id || 'unknown';
}

function ensureTimerStore(app) {
  if (!app.locals.timerStore) {
    app.locals.timerStore = new Map();
  }
  return app.locals.timerStore;
}

router.post('/timers/schedule', async (req, res) => {
  const requestId = req.requestId || ulid();
  const { delay_seconds, payload = null } = req.body || {};

  if (!Number.isFinite(delay_seconds) || delay_seconds <= 0 || delay_seconds > 86400) {
    return res.status(400).json({ error: 'Invalid delay_seconds (must be 1..86400)', requestId });
  }
  

  const timerId = ulid();
  
  // Use blockchain time from NEAR instead of system time
  const now = timezoneService._getCachedNearMsOrThrow();
  const delayMs = Math.floor(delay_seconds * 1000);
  const scheduledAt = new Date(now).toISOString();
  const executeAt = new Date(now + delayMs).toISOString();
  const sessionKey = getSessionKey(req);
  const userId = req.user?.id || 'unknown';

  const store = ensureTimerStore(req.app);
  let sessionMap = store.get(sessionKey);
  if (!sessionMap) {
    sessionMap = new Map();
    store.set(sessionKey, sessionMap);
  }

  const event = {
    timer_id: timerId,
    session_key: sessionKey,
    user_id: userId,
    scheduled_at: scheduledAt,
    execute_at: executeAt,
    delay_seconds: delay_seconds,
    payload
  };

  sessionMap.set(timerId, event);

  const ctx = { component: 'TimerRoutes', requestId, timerId, sessionKey, userId, delay_seconds, executeAt };
  logger.infoWithContext('Timer scheduled', ctx);

  const handle = setTimeout(async () => {
    // Use blockchain time from NEAR for webhook timestamp
    const firedAtMs = timezoneService._getCachedNearMsOrThrow();
    const firedAt = new Date(firedAtMs).toISOString();
    const body = {
      timer_id: timerId,
      scheduled_at: scheduledAt,
      execute_at: executeAt,
      fired_at: firedAt,
      user_id: userId,
      session_key: sessionKey,
      payload
    };
    try {
      // Use blockchain time for duration measurement
      const start = timezoneService._getCachedNearMsOrThrow();
      const client = req.app?.locals?.roditClient;
      if (!client || typeof client.send_webhook !== 'function') {
        throw new Error('Webhook sender unavailable');
      }
      await client.send_webhook(body, req);
      const duration = timezoneService._getCachedNearMsOrThrow() - start;
      logger.infoWithContext('Timer callback sent', { ...ctx, firedAt, duration });
      logger.metric('timer_callback', duration, { result: 'success' });
    } catch (error) {
      logger.errorWithContext('Timer callback error', { ...ctx, firedAt, error: error.message }, error);
      logger.metric('timer_callback', 0, { result: 'error' });
    } finally {
      const sm = store.get(sessionKey);
      if (sm) {
        sm.delete(timerId);
        if (sm.size === 0) store.delete(sessionKey);
      }
    }
  }, delayMs);

  event.timeoutHandle = handle;

  res.status(202).json({ timer_id: timerId, delay_seconds, scheduled_at: scheduledAt, execute_at: executeAt, requestId });
});

module.exports = router;
