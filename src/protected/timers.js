const express = require('express');
const router = express.Router();
const { ulid } = require('ulid');
const { logger } = require('@rodit/rodit-auth-be');
const TimeZoneService = require('../lib/timezone-service');
const TimerPersistence = require('../lib/timer-persistence');

// Initialize timezone service for blockchain time
const timezoneService = new TimeZoneService();

// Initialize timer persistence
const timerPersistence = new TimerPersistence();

// Maximum timer delay: 48 hours (172800 seconds)
// Rationale: Balances flexibility with resource management. With hourly persistence,
// timers can survive server restarts with minimal data loss (max 1 hour window).
const MAX_DELAY_SECONDS = 172800; // 48 hours

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

  // Validate delay_seconds according to OpenAPI spec: required, number, minimum: 1, maximum: 172800 (48 hours)
  if (delay_seconds === undefined || delay_seconds === null) {
    return res.status(400).json({ error: 'delay_seconds is required', requestId });
  }
  
  if (!Number.isFinite(delay_seconds)) {
    return res.status(400).json({ error: 'delay_seconds must be a number', requestId });
  }
  
  if (delay_seconds < 1) {
    return res.status(400).json({ error: 'delay_seconds must be at least 1', requestId });
  }
  
  if (delay_seconds > MAX_DELAY_SECONDS) {
    return res.status(400).json({ error: `delay_seconds must be at most ${MAX_DELAY_SECONDS} (48 hours)`, requestId });
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
    // Fetch fresh NEAR blockchain timestamp for fired_at
    // NEAR blockchain time advances in ~600ms blocks, so fresh fetches can return
    // older timestamps than cached values. Ensure fired_at >= execute_at for temporal consistency.
    let firedAtMs;
    try {
      const timestampNs = await require('@rodit/rodit-auth-be').blockchainService.nearorg_rpc_timestamp();
      firedAtMs = Math.floor(timestampNs / 1_000_000);
    } catch (error) {
      // Fallback to cached value if fresh fetch fails
      logger.warnWithContext('Failed to fetch fresh NEAR timestamp, using cached', { ...ctx, error: error.message });
      firedAtMs = timezoneService._getCachedNearMsOrThrow();
    }
    // Ensure fired_at is never earlier than execute_at (blockchain time granularity issue)
    const executeAtMs = new Date(executeAt).getTime();
    firedAtMs = Math.max(firedAtMs, executeAtMs);
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

/**
 * Restore timers from persistence on server startup
 * Reschedules timers that haven't fired yet, skips expired ones
 */
async function restoreTimers(app) {
  const store = ensureTimerStore(app);
  const savedTimers = await timerPersistence.loadTimers();
  
  const now = timezoneService._getCachedNearMsOrThrow();
  let restored = 0;
  let skipped = 0;
  
  for (const timer of savedTimers) {
    const executeAtMs = new Date(timer.execute_at).getTime();
    const remainingMs = executeAtMs - now;
    
    // Skip timers that should have already fired (never fire late)
    if (remainingMs <= 0) {
      skipped++;
      logger.debugWithContext('Skipping expired timer', {
        component: 'TimerRestore',
        timer_id: timer.timer_id,
        execute_at: timer.execute_at,
        expired_by_ms: Math.abs(remainingMs)
      });
      continue;
    }
    
    // Reschedule the timer
    let sessionMap = store.get(timer.session_key);
    if (!sessionMap) {
      sessionMap = new Map();
      store.set(timer.session_key, sessionMap);
    }
    
    const event = {
      timer_id: timer.timer_id,
      session_key: timer.session_key,
      user_id: timer.user_id,
      scheduled_at: timer.scheduled_at,
      execute_at: timer.execute_at,
      delay_seconds: timer.delay_seconds,
      payload: timer.payload
    };
    
    const handle = setTimeout(async () => {
      // Fetch fresh NEAR blockchain timestamp for fired_at
      // Ensure fired_at >= execute_at for temporal consistency
      let firedAtMs;
      try {
        const timestampNs = await require('@rodit/rodit-auth-be').blockchainService.nearorg_rpc_timestamp();
        firedAtMs = Math.floor(timestampNs / 1_000_000);
      } catch (error) {
        // Fallback to cached value if fresh fetch fails
        logger.warnWithContext('Failed to fetch fresh NEAR timestamp for restored timer, using cached', {
          component: 'TimerRestore',
          timer_id: timer.timer_id,
          error: error.message
        });
        firedAtMs = timezoneService._getCachedNearMsOrThrow();
      }
      // Ensure fired_at is never earlier than execute_at (blockchain time granularity issue)
      const executeAtMs = new Date(timer.execute_at).getTime();
      firedAtMs = Math.max(firedAtMs, executeAtMs);
      const firedAt = new Date(firedAtMs).toISOString();
      const body = {
        timer_id: timer.timer_id,
        scheduled_at: timer.scheduled_at,
        execute_at: timer.execute_at,
        fired_at: firedAt,
        user_id: timer.user_id,
        session_key: timer.session_key,
        payload: timer.payload
      };
      
      try {
        const start = timezoneService._getCachedNearMsOrThrow();
        const client = app?.locals?.roditClient;
        if (!client || typeof client.send_webhook !== 'function') {
          throw new Error('Webhook sender unavailable');
        }
        await client.send_webhook(body, null);
        const duration = timezoneService._getCachedNearMsOrThrow() - start;
        logger.infoWithContext('Restored timer callback sent', {
          component: 'TimerRestore',
          timer_id: timer.timer_id,
          firedAt,
          duration
        });
        logger.metric('timer_callback', duration, { result: 'success', restored: true });
      } catch (error) {
        logger.errorWithContext('Restored timer callback error', {
          component: 'TimerRestore',
          timer_id: timer.timer_id,
          firedAt,
          error: error.message
        }, error);
        logger.metric('timer_callback', 0, { result: 'error', restored: true });
      } finally {
        const sm = store.get(timer.session_key);
        if (sm) {
          sm.delete(timer.timer_id);
          if (sm.size === 0) store.delete(timer.session_key);
        }
      }
    }, remainingMs);
    
    event.timeoutHandle = handle;
    sessionMap.set(timer.timer_id, event);
    restored++;
  }
  
  logger.infoWithContext('Timer restoration complete', {
    component: 'TimerRestore',
    total: savedTimers.length,
    restored,
    skipped
  });
  
  return { restored, skipped, total: savedTimers.length };
}

/**
 * Initialize timer persistence and restoration
 * Call this after app is fully initialized
 */
async function initializeTimerPersistence(app) {
  const store = ensureTimerStore(app);
  
  // Restore timers from disk
  await restoreTimers(app);
  
  // Start hourly auto-save
  timerPersistence.startAutoSave(store);
  
  // Graceful shutdown: save timers before exit
  const gracefulShutdown = async (signal) => {
    logger.infoWithContext(`Received ${signal}, saving timers before shutdown`, {
      component: 'TimerPersistence'
    });
    await timerPersistence.stopAutoSave(store);
    process.exit(0);
  };
  
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

module.exports = router;
module.exports.initializeTimerPersistence = initializeTimerPersistence;
module.exports.MAX_DELAY_SECONDS = MAX_DELAY_SECONDS;
