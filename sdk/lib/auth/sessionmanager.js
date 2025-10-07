const { ulid } = require('ulid');
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const config = require('../../services/configsdk');
const SESSION_CLEANUP_INTERVAL = config.get('SESSION_CLEANUP_INTERVAL'); // 1 hour in milliseconds
const SESSION_TOKEN_RETENTION_PERIOD = config.get('SESSION_TOKEN_RETENTION_PERIOD'); // 7 days in seconds

// Try to load express-session if available in host app
let sessionLib = null;
try {
  // eslint-disable-next-line import/no-extraneous-dependencies
  sessionLib = require('express-session');
  logger.info('express-session detected; SessionManager can use express-compatible stores');
} catch (e) {
  // Optional dependency — we gracefully fall back to internal memory storage
  sessionLib = null;
}

/**
 * Adapter to wrap an express-session Store and expose the SDK's storage interface
 * Required SDK interface: { get, set, delete, keys, size, clear, getAll? }
 */
class ExpressSessionStoreAdapter {
  constructor(store) {
    if (!store || typeof store !== 'object') {
      throw new Error('ExpressSessionStoreAdapter requires a valid store instance');
    }
    // Minimal express-session Store methods we rely on
    const required = ['get', 'set', 'destroy'];
    const missing = required.filter((m) => typeof store[m] !== 'function');
    if (missing.length) {
      throw new Error(`Provided express-session store is missing methods: ${missing.join(', ')}`);
    }
    this.store = store;
  }

  async get(sessionId) {
    return new Promise((resolve) => {
      this.store.get(sessionId, (err, sess) => {
        if (err) return resolve(null);
        // Allow storing our own session objects directly
        resolve(sess || null);
      });
    });
  }

  async set(sessionId, session) {
    // Help express-session stores compute TTL by providing cookie.maxAge when possible
    try {
      if (session && typeof session === 'object' && session.expiresAt) {
        const nowSec = Math.floor(Date.now() / 1000);
        const ttlMs = Math.max(0, (session.expiresAt - nowSec) * 1000);
        if (!session.cookie || typeof session.cookie !== 'object') {
          session.cookie = {};
        }
        if (typeof session.cookie.maxAge !== 'number') {
          session.cookie.maxAge = ttlMs; // Many stores read cookie.maxAge for TTL
        }
        if (typeof session.cookie.originalMaxAge !== 'number') {
          session.cookie.originalMaxAge = ttlMs;
        }
      }
    } catch (_) {
      // Non-fatal: continue without cookie hints
    }

    return new Promise((resolve) => {
      this.store.set(sessionId, session, (err) => {
        if (err) return resolve(false);
        resolve(true);
      });
    });
  }

  async delete(sessionId) {
    return new Promise((resolve) => {
      this.store.destroy(sessionId, (err) => {
        if (err) return resolve(false);
        resolve(true);
      });
    });
  }

  async keys() {
    // Non-standard; best-effort using .all() if available
    if (typeof this.store.all === 'function') {
      return new Promise((resolve) => {
        this.store.all((err, sessions) => {
          if (err || !sessions) return resolve([]);
          if (Array.isArray(sessions)) {
            // MemoryStore typically returns array of session objects without ids; not standardized
            // Some stores return array of session records with an id property
            const ids = sessions
              .map((s) => s?.id || s?.sessionId || s?.sid)
              .filter(Boolean);
            return resolve(ids);
          }
          // Some stores return an object map { sid: session }
          resolve(Object.keys(sessions));
        });
      });
    }
    // If not supported, return empty (SDK falls back where possible)
    return [];
  }

  async size() {
    if (typeof this.store.length === 'function') {
      return new Promise((resolve) => {
        this.store.length((err, length) => {
          if (err) return resolve(0);
          resolve(typeof length === 'number' ? length : 0);
        });
      });
    }
    if (typeof this.store.all === 'function') {
      const all = await this.getAll();
      return Array.isArray(all) ? all.length : (all ? Object.keys(all).length : 0);
    }
    return 0;
  }

  async clear() {
    if (typeof this.store.clear === 'function') {
      return new Promise((resolve) => {
        this.store.clear((err) => resolve(!err));
      });
    }
    // Fallback: enumerate keys and destroy
    const ids = await this.keys();
    let ok = true;
    for (const id of ids) {
      // eslint-disable-next-line no-await-in-loop
      const res = await this.delete(id);
      ok = ok && res;
    }
    return ok;
  }

  async getAll() {
    if (typeof this.store.all === 'function') {
      return new Promise((resolve) => {
        this.store.all((err, sessions) => {
          if (err) return resolve([]);
          resolve(sessions || []);
        });
      });
    }
    // Not supported; reconstruct is not feasible without keys -> return empty
    return [];
  }

  async getStorageInfo() {
    const info = {
      type: 'ExpressSessionStoreAdapter',
      storeType: this.store?.constructor?.name || 'UnknownStore',
      features: {
        hasAll: typeof this.store.all === 'function',
        hasLength: typeof this.store.length === 'function',
        hasClear: typeof this.store.clear === 'function',
      },
      timestamp: new Date().toISOString(),
    };
    try {
      const count = await this.size();
      info.sessionCount = count;
    } catch (_) {
      info.sessionCount = undefined;
    }
    return info;
  }
}
class InMemorySessionStorage {
  constructor() {
    this.sessions = new Map();
  }

  async get(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    
    // Check if session is expired and auto-cleanup
    const now = Math.floor(Date.now() / 1000);
    if (session.expiresAt && session.expiresAt < now) {
      // Session is expired, remove it
      this.sessions.delete(sessionId);
      return null;
    }
    
    return session;
  }

  async set(sessionId, session) {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new Error('sessionId must be a non-empty string');
    }
    
    // Add timestamp for tracking
    if (session && typeof session === 'object') {
      session.updatedAt = Math.floor(Date.now() / 1000);
    }
    
    this.sessions.set(sessionId, session);
    return true;
  }

  async delete(sessionId) {
    return this.sessions.delete(sessionId);
  }

  async keys() {
    return Array.from(this.sessions.keys());
  }

  async size() {
    return this.sessions.size;
  }

  async clear() {
    this.sessions.clear();
    return true;
  }

  async getAll() {
    // Return an array of all session objects
    return Array.from(this.sessions.values());
  }


  async getStorageInfo() {
    return {
      type: 'InMemorySessionStorage',
      sessionCount: this.sessions.size,
      memoryUsage: process.memoryUsage ? process.memoryUsage() : 'unavailable',
      timestamp: new Date().toISOString()
    };
  }

  // Validate session structure
  _validateSession(session) {
    if (!session || typeof session !== 'object') {
      return false;
    }
    const required = ['id', 'status', 'createdAt'];
    return required.every(prop => prop in session);
  }
}

// Default storage: standalone in-memory store (no express-session dependency)
// If applications want Redis/DB/etc they must provide an express-session Store via setExpressSessionStore()
const defaultStorage = new InMemorySessionStorage();

let currentStorage = defaultStorage;

function setStorage(customStorage) {
  if (!customStorage || typeof customStorage !== 'object') {
    throw new Error('setStorage(customStorage) requires a storage object');
  }
  
  const required = ['get', 'set', 'delete', 'keys', 'size', 'clear'];
  const missing = required.filter(method => typeof customStorage[method] !== 'function');
  
  if (missing.length) {
    throw new Error(`Injected storage is missing methods: ${missing.join(', ')}`);
  }
  

  
  currentStorage = customStorage;
}

// Allow direct injection of an express-session Store and wrap it with our adapter
function setExpressSessionStore(expressSessionStore) {
  if (!sessionLib) {
    throw new Error('express-session is not installed; cannot set express-session store');
  }
  const adapter = new ExpressSessionStoreAdapter(expressSessionStore);
  currentStorage = adapter;
  logger.info('Session storage set via express-session store', {
    storeType: expressSessionStore?.constructor?.name,
  });
}

function configureStorageFromConfig() {
  let storageType;
  try {
    storageType = config.get('SESSION_STORAGE_TYPE');
  } catch (_) {
    // Keep default storage
    return;
  }

  const type = String(storageType || '').toLowerCase();

  switch (type) {
    case 'memory':
      // Use standalone in-memory store
      currentStorage = new InMemorySessionStorage();
      logger.info('Configured session storage: standalone InMemorySessionStorage');
      return;

    case 'express':
    case 'express-session':
      if (!sessionLib || !sessionLib.MemoryStore) {
        logger.warn('express-session not installed. Falling back to standalone InMemorySessionStorage');
        currentStorage = new InMemorySessionStorage();
        return;
      }
      currentStorage = new ExpressSessionStoreAdapter(new sessionLib.MemoryStore());
      logger.info('Configured session storage: express-session MemoryStore (override with setExpressSessionStore for Redis/DB/etc)');
      return;

    default:
      logger.warn(`Unknown SESSION_STORAGE_TYPE='${storageType}'. Using standalone InMemorySessionStorage.`);
      currentStorage = new InMemorySessionStorage();
      return;
  }
}

// Optional helper to create a real express-session middleware using the current store
function createExpressSessionMiddleware(options = {}) {
  if (!sessionLib) {
    logger.warn('express-session not installed; returning no-op session middleware');
    return (req, res, next) => next();
  }
  const secret = options.secret || process.env.SESSION_SECRET || 'change-me';
  const store = (currentStorage instanceof ExpressSessionStoreAdapter)
    ? currentStorage.store
    : new sessionLib.MemoryStore();

  return sessionLib({
    saveUninitialized: false,
    resave: false,
    ...options,
    secret,
    store,
  });
}

class SessionManager {
  constructor() {
    const instanceId = ulid();
    const baseContext = createLogContext("SessionManager", "constructor", { instanceId });

    logger.infoWithContext("SessionManager instance created", {
      ...baseContext,
      instanceId,
      timestamp: new Date().toISOString(),
      isSingleton: true
    });
    
    // Note: Token invalidation is now handled via session state checking
    // No separate invalidatedTokens Map needed - tokens are invalid when their session is closed
    
    // Token validation cache - trades security for performance
    // Cache stores validation results with TTL to reduce storage lookups
    this._validationCache = new Map();
    this._validationCacheTTL = config.get('TOKEN_VALIDATION_CACHE_TTL', 5000);
    
    // Cleanup interval reference
    this.cleanupInterval = null;
    
    this._instanceId = instanceId;

    logger.infoWithContext("Token validation cache initialized", {
      ...baseContext,
      cacheTTL: this._validationCacheTTL,
      cacheEnabled: this._validationCacheTTL > 0
    });
  }

  // Storage facade - delegates to current storage with proper binding
  get storage() {
    return {
      get: currentStorage.get.bind(currentStorage),
      set: currentStorage.set.bind(currentStorage),
      delete: currentStorage.delete.bind(currentStorage),
      keys: currentStorage.keys.bind(currentStorage),
      size: currentStorage.size.bind(currentStorage),
      getAll: currentStorage.getAll ? currentStorage.getAll.bind(currentStorage) : undefined
    };
  }

  /**
   * Get cached validation result for a token
   * @private
   */
  _getCachedValidation(token) {
    if (this._validationCacheTTL <= 0) return undefined;
    
    const entry = this._validationCache.get(token);
    if (!entry) return undefined;
    
    // Check if entry has expired
    if (entry.expiresAt && entry.expiresAt <= Date.now()) {
      this._validationCache.delete(token);
      return undefined;
    }
    
    return entry.value;
  }

  /**
   * Cache validation result for a token
   * @private
   */
  _setCachedValidation(token, isInvalidated, sessionId = null) {
    if (this._validationCacheTTL <= 0) return; // Caching disabled
    
    const expiresAt = this._validationCacheTTL > 0 ? Date.now() + this._validationCacheTTL : 0;
    this._validationCache.set(token, { 
      value: isInvalidated, 
      expiresAt,
      sessionId,
      cachedAt: Date.now()
    });
  }

  /**
   * Invalidate cache entry for a token (called when session is closed)
   * @private
   */
  _invalidateCachedValidation(token) {
    this._validationCache.delete(token);
  }

  /**
   * Invalidate all cache entries for a specific session
   * This is called when a session is closed to immediately invalidate all tokens for that session
   * @private
   */
  _invalidateCachedValidationBySession(sessionId) {
    if (!sessionId) return;
    
    let invalidatedCount = 0;
    for (const [token, entry] of this._validationCache.entries()) {
      if (entry.sessionId === sessionId) {
        this._validationCache.delete(token);
        invalidatedCount++;
      }
    }
    
    if (invalidatedCount > 0) {
      logger.debugWithContext("Invalidated cached validations for closed session", {
        component: "SessionManager",
        method: "_invalidateCachedValidationBySession",
        sessionId,
        invalidatedCount
      });
    }
  }

  /**
   * Get cache statistics for monitoring
   */
  getValidationCacheStats() {
    const now = Date.now();
    let validEntries = 0;
    let expiredEntries = 0;
    
    for (const [, entry] of this._validationCache.entries()) {
      if (entry.expiresAt && entry.expiresAt <= now) {
        expiredEntries++;
      } else {
        validEntries++;
      }
    }
    
    return {
      totalEntries: this._validationCache.size,
      validEntries,
      expiredEntries,
      cacheTTL: this._validationCacheTTL,
      cacheEnabled: this._validationCacheTTL > 0
    };
  }


  _generateSessionId(roditId) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "_generateSessionId", { requestId, roditId });
        
    const sessionId = `sess_${roditId}_${ulid()}`;
 
    logger.debugWithContext("Generated session ID", {
      ...baseContext,
      sessionId,
      roditId
    });
    
    return sessionId;
  }

  async createSession(sessionData) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "createSession", { requestId });
    
    // Get current active session count for metrics
    const activeSessionCount = await this.getActiveSessionCount();
    
    try {
      if (!sessionData || !sessionData.roditId) {
        throw new Error('Missing required session data');
      }

      const sessionId = this._generateSessionId(sessionData.roditId);
      const now = Math.floor(Date.now() / 1000);
      
      // Create the session object
      const session = {
        id: sessionId,
        roditId: sessionData.roditId,
        ownerId: sessionData.ownerId,
        createdAt: sessionData.createdAt || now,
        expiresAt: sessionData.expiresAt,
        lastAccessedAt: now,
        status: 'active',
        metadata: sessionData.metadata || {},
      };
      
      // Store the session
      await this.storage.set(sessionId, session);
      
      const duration = Date.now() - startTime;
      
      // Verify the session was stored correctly
      const storedSession = await this.storage.get(sessionId);
      const verificationSuccess = !!storedSession;
      
      logger.infoWithContext("Session created and stored", {
        ...baseContext,
        sessionId,
        sessionStatus: session.status,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        verificationSuccess,
        sessionManagerInstanceId: this._instanceId,
        storageBackend: currentStorage?.store ? currentStorage.store.constructor.name : currentStorage.constructor.name,
        duration,
        sessionObjectValid: !!session,
        sessionIdValid: !!session?.id,
        sessionIdType: typeof session?.id
      });
      
      // Validate session object before returning
      if (!session || !session.id) {
        logger.errorWithContext("Created session is invalid", {
          ...baseContext,
          sessionObject: session,
          sessionId,
          sessionManagerInstanceId: this._instanceId
        });
        throw new Error("Session creation resulted in invalid session object");
      }
      
      return session;
    } catch (error) {
      const duration = Date.now() - startTime;
        
      throw error;
    }
  }


  async getSession(sessionId) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "getSession", { 
      requestId, 
      sessionId 
    });
    
    try {
      const session = await this.storage.get(sessionId);
      const now = Math.floor(Date.now() / 1000);
      
      if (!session) {
        const duration = Date.now() - startTime;
        
        logger.warnWithContext("Session not found in storage", {
          ...baseContext,
          sessionId,
          sessionManagerInstanceId: this._instanceId,
          storageBackend: currentStorage?.store ? currentStorage.store.constructor.name : currentStorage.constructor.name,
          duration,
          currentTimestamp: now
        });
        
        return null;
      }
      
      // Update last accessed time
      session.lastAccessedAt = now;
      // Persist updated access time back to storage
      await this.storage.set(sessionId, session);
      
      const duration = Date.now() - startTime;
      
      logger.debugWithContext("Session retrieved successfully", {
        ...baseContext,
        sessionId,
        sessionStatus: session.status,
        expiresAt: session.expiresAt,
        lastAccessedAt: session.lastAccessedAt,
        sessionManagerInstanceId: this._instanceId,
        storageBackend: currentStorage?.store ? currentStorage.store.constructor.name : currentStorage.constructor.name,
        duration
      });

      return session;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      logger.errorWithContext("Error retrieving session", {
        ...baseContext,
        sessionId,
        error: error.message,
        sessionManagerInstanceId: this._instanceId,
        duration
      });

      return null;
    }
  }


  async updateSession(sessionId, updates) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "updateSession", { 
      requestId, 
      sessionId,
      updatedFields: updates ? Object.keys(updates) : [] 
    });
    

    
    try {
      // Load session from configured storage
      const session = await this.storage.get(sessionId);
      
      if (!session) {
        return null;
      }
      
      // Apply updates except id which should be immutable
      Object.entries(updates).forEach(([key, value]) => {
        if (key !== 'id') {
          session[key] = value;
        }
      });
      
      // Update last accessed time
      session.lastAccessedAt = Math.floor(Date.now() / 1000);
      
      // Store updated session in storage
      await this.storage.set(sessionId, session);
      
      const duration = Date.now() - startTime;
      
            
      return session;
    } catch (error) {
      const duration = Date.now() - startTime;
    
      
      return null;
    }
  }

  async closeSession(sessionId, reason = 'user_logout', token = null) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "closeSession", { 
      requestId, 
      sessionId,
      reason,
      hasToken: !!token
    });
    
    try {
      const session = await this.storage.get(sessionId);
      
      if (!session) {
        // Enhanced debugging for session not found
        const allSessionIds = await this.storage.keys();
        const sessionCount = await this.storage.size();

        
        return true; // Changed to true - allow logout to succeed
      }
      
      // Update session status
      session.status = 'closed';
      session.closedAt = Math.floor(Date.now() / 1000);
      session.closeReason = reason;
      
      // Store updated session
      await this.storage.set(sessionId, session);
      
      // CRITICAL: Immediately invalidate all cached validations for this session
      // This ensures tokens are rejected immediately after logout, not after cache TTL
      this._invalidateCachedValidationBySession(sessionId);
      
      // Also invalidate the specific token if provided
      if (token) {
        this._invalidateCachedValidation(token);
      }
      
      logger.debugWithContext("Session closed and cache invalidated", {
        ...baseContext,
        sessionId,
        cacheInvalidated: true
      });
            
      const duration = Date.now() - startTime;
      
      return true;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      return false;
    }
  }


  async invalidateToken(token, reason = 'user_logout', sessionId = null) {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext("SessionManager", "invalidateToken", { 
      requestId, 
      reason,
      sessionId: sessionId || 'will_extract_from_token'
    });
    
    try {
      // If sessionId not provided, extract it from the token
      let targetSessionId = sessionId;
      if (!targetSessionId && token) {
        try {
          const tokenParts = token.split('.');
          if (tokenParts.length === 3) {
            const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64url').toString());
            targetSessionId = payload.session_id;
          }
        } catch (decodeError) {

        }
      }
      
      if (!targetSessionId) {
        return false;
      }
      
      // Close the session - this will invalidate the token
      const sessionClosed = await this.closeSession(targetSessionId, reason, null); // Don't pass token to avoid recursion
      
      const duration = Date.now() - startTime;

      
      return sessionClosed;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      
      return false;
    }
  }
  

  async isTokenInvalidated(token) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "isTokenInvalidated", { requestId });
      
    if (!token) {
      return true; // No token = invalidated
    }
    
    try {
      // Check cache first for performance
      const cachedResult = this._getCachedValidation(token);
      if (cachedResult !== undefined) {
        const duration = Date.now() - startTime;
        logger.debugWithContext("Token validation cache hit", {
          ...baseContext,
          isInvalidated: cachedResult,
          cacheHit: true,
          duration,
          tokenPrefix: token.substring(0, 20) + '...'
        });
        return cachedResult;
      }
      
      // Cache miss - perform full validation
      // Decode JWT token to extract session_id
      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        return true; // Invalid format = invalidated
      }
      
      // Decode the payload (second part) using base64url
      const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64url').toString());
      const sessionId = payload.session_id;
      
      if (!sessionId) {
        return true; // No session ID = invalidated
      }
      
      // Check if session exists and is active
      const session = await this.storage.get(sessionId);
      const now = Math.floor(Date.now() / 1000);
      
      let isInvalidated = false;
      let reason = null;
      
      if (!session) {
        isInvalidated = true;
        reason = "session_not_found";
      } else if (session.status !== 'active') {
        isInvalidated = true;
        reason = `session_status_${session.status}`;
      } else if (session.expiresAt && session.expiresAt < now) {
        isInvalidated = true;
        reason = "session_expired";
      }
      
      // Cache the result for future requests
      this._setCachedValidation(token, isInvalidated, sessionId);
      
      const duration = Date.now() - startTime;
      
      logger.infoWithContext("Token invalidation check completed", {
        ...baseContext,
        sessionId,
        isInvalidated,
        reason,
        sessionFound: !!session,
        sessionStatus: session?.status,
        sessionExpiresAt: session?.expiresAt,
        currentTimestamp: now,
        sessionManagerInstanceId: this._instanceId,
        tokenPrefix: token.substring(0, 20) + '...',
        cacheHit: false,
        cacheTTL: this._validationCacheTTL,
        duration
      });

      return isInvalidated;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      // If we can't check due to error, assume it's invalidated for security
      return true;
    }
  }
  

  async getTokenInvalidationInfo(token) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "getTokenInvalidationInfo", { requestId });
    
    
    if (!token) {
      return {
        reason: "no_token_provided",
        invalidatedAt: Math.floor(Date.now() / 1000),
        timestamp: new Date().toISOString(),
        sessionId: null
      };
    }
    
    try {
      // Decode JWT token to extract session_id
      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        return {
          reason: "invalid_jwt_format",
          invalidatedAt: Math.floor(Date.now() / 1000),
          timestamp: new Date().toISOString(),
          sessionId: null
        };
      }
      
      const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
      const sessionId = payload.session_id;
      
      if (!sessionId) {
        return {
          reason: "no_session_id_in_token",
          invalidatedAt: Math.floor(Date.now() / 1000),
          timestamp: new Date().toISOString(),
          sessionId: null
        };
      }
      
      // Check session state
      const session = await this.storage.get(sessionId);
      const now = Math.floor(Date.now() / 1000);
      
      let invalidationInfo = null;
      
      if (!session) {
        invalidationInfo = {
          reason: "session_not_found",
          invalidatedAt: now,
          timestamp: new Date().toISOString(),
          sessionId
        };
      } else if (session.status !== 'active') {
        invalidationInfo = {
          reason: `session_status_${session.status}`,
          invalidatedAt: session.closedAt || now,
          timestamp: session.closedAt ? new Date(session.closedAt * 1000).toISOString() : new Date().toISOString(),
          sessionId,
          closeReason: session.closeReason
        };
      } else if (session.expiresAt && session.expiresAt < now) {
        invalidationInfo = {
          reason: "session_expired",
          invalidatedAt: session.expiresAt,
          timestamp: new Date(session.expiresAt * 1000).toISOString(),
          sessionId
        };
      }
      
      const duration = Date.now() - startTime;
            return invalidationInfo;
    } catch (error) {
      const duration = Date.now() - startTime;
  
      
      // Return error info
      return {
        reason: "error_checking_session",
        invalidatedAt: Math.floor(Date.now() / 1000),
        timestamp: new Date().toISOString(),
        sessionId: null,
        error: error.message
      };
    }
  }
  

  hashToken(token) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "hashToken", { requestId });
    
    try {
      const crypto = require('crypto');
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      
      const duration = Date.now() - startTime;
      
      
      return hash;
    } catch (error) {
      const duration = Date.now() - startTime;

      
      throw error; // Rethrow as this is a critical operation
    }
  }
  

  async isSessionActive(sessionId) {
    if (!sessionId) return false;
    const session = await this.getSession(sessionId);
    // Session is active if it exists, isn't closed or expired
    return !!(session && session.status === 'active');
  }

  async cleanupExpiredSessions() {
    const requestId = ulid();
    const startTime = Date.now();
    const now = Math.floor(Date.now() / 1000);
    let removedCount = 0;
    const baseContext = createLogContext("SessionManager", "cleanupExpiredSessions", { requestId });
    
    try {
      // Get all sessions from storage (support backends without getAll)
      let allSessions = [];
      if (typeof this.storage.getAll === 'function') {
        allSessions = await this.storage.getAll();
      } else {
        const ids = await this.storage.keys();
        for (const id of ids) {
          const s = await this.storage.get(id);
          if (s) allSessions.push(s);
        }
      }
      
      logger.infoWithContext("Starting session cleanup", {
        ...baseContext,
        totalSessions: allSessions.length,
        currentTimestamp: now,
        sessionManagerInstanceId: this._instanceId
      });
      
      // Find expired sessions
      for (const session of allSessions) {
        const sessionId = session.id || session.sessionId;
        if (!sessionId) {
          continue;
        }
        
        const isExpired = session.expiresAt && session.expiresAt < now;
        const isOldClosed = session.status === 'closed' && session.closedAt < now - 86400;
        
        if (isExpired || isOldClosed) {
          logger.infoWithContext("Removing expired/old session", {
            ...baseContext,
            sessionId,
            sessionStatus: session.status,
            expiresAt: session.expiresAt,
            closedAt: session.closedAt,
            currentTimestamp: now,
            reason: isExpired ? 'expired' : 'old_closed',
            sessionManagerInstanceId: this._instanceId
          });
          
          await this.storage.delete(sessionId);
          removedCount++;
        } else {
          logger.debugWithContext("Session kept during cleanup", {
            ...baseContext,
            sessionId,
            sessionStatus: session.status,
            expiresAt: session.expiresAt,
            currentTimestamp: now,
            sessionManagerInstanceId: this._instanceId
          });
        }
      }
      
      const duration = Date.now() - startTime;
      
      logger.infoWithContext("Session cleanup completed", {
        ...baseContext,
        removedCount,
        totalSessionsBefore: allSessions.length,
        remainingSessions: allSessions.length - removedCount,
        sessionManagerInstanceId: this._instanceId,
        duration
      });
      
      return removedCount;
    } catch (error) {

      
      return 0;
    }
  }


  async findSessionsByRoditId(roditId) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "findSessionsByRoditId", { requestId, roditId });
    
    
    try {
      let result = [];
      // Get sessions from storage
      let allSessions = [];
      if (typeof this.storage.getAll === 'function') {
        allSessions = await this.storage.getAll();
      } else {
        const ids = await this.storage.keys();
        for (const id of ids) {
          const s = await this.storage.get(id);
          if (s) allSessions.push(s);
        }
      }
      result = allSessions.filter(s => s && s.roditId === roditId);
      
      const duration = Date.now() - startTime;
      
      
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
          
      
      return [];
    }
  }


  async getActiveSessionCount() {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext("SessionManager", "getActiveSessionCount", { requestId });
    
    try {
      let count = 0;
      const now = Math.floor(Date.now() / 1000);
      
      // Get all sessions from storage with fallback mechanisms
      let allSessions = [];
      try {
        // First try to use getAll if available
        if (this.storage.getAll) {
          allSessions = await this.storage.getAll();
        } else {
          // Fall back to getting keys and fetching each one
          const ids = await this.storage.keys();
          for (const id of ids) {
            try {
              const s = await this.storage.get(id);
              if (s) allSessions.push(s);
            } catch (err) {
              // Skip any invalid sessions
              continue;
            }
          }
        }
      } catch (err) {
        // If we can't get sessions, return 0
        logger.error('Error getting sessions', { ...baseContext, error: err.message });
        return 0;
      }
      
      // Count active sessions
      for (const session of allSessions) {
        try {
          if (session && 
              typeof session === 'object' && 
              session.status === 'active' && 
              (!session.expiresAt || session.expiresAt > now)) {
            count++;
          }
        } catch (err) {
          // Skip any invalid session objects
          continue;
        }
      }
      
      const duration = Date.now() - startTime;
      logger.debug('Active session count calculated', { ...baseContext, count, duration });
      
      return count;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Error in getActiveSessionCount', { 
        ...baseContext, 
        error: error.message, 
        duration 
      });
      
      // Return 0 on any error to ensure the application remains available
      return 0;
    }
  }

  startCleanupJob(interval = SESSION_CLEANUP_INTERVAL) {
    const requestId = ulid();
    
    const baseContext = createLogContext(
      "SessionManager",
      "startCleanupJob",
      {
        requestId,
        intervalMs: interval,
        intervalSeconds: interval / 1000
      }
    );
    
    // Clear any existing interval
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    // Schedule the cleanup job
    this.cleanupInterval = setInterval(async () => {
      const cleanupRequestId = ulid();
      const startTime = Date.now();
      
      const cleanupContext = createLogContext(
        "SessionManager",
        "scheduledCleanup",
        {
          requestId: cleanupRequestId,
          intervalSeconds: interval / 1000
        }
      );
      
      
      try {
        const removedCount = await this.cleanupExpiredSessions();

        const duration = Date.now() - startTime;
   
      } catch (error) {
        const duration = Date.now() - startTime;

      }
    }, interval);

  }


  stopCleanupJob() {
    const requestId = ulid();
    
    const baseContext = createLogContext(
      "SessionManager",
      "stopCleanupJob",
      { requestId }
    );
    
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
      
    } else {
    }
  }

  async runManualCleanup(tokenRetentionPeriod = SESSION_TOKEN_RETENTION_PERIOD) {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext(
      "SessionManager",
      "runManualCleanup",
      { requestId }
    );
    
    
    try {
      const removedSessionsCount = await this.cleanupExpiredSessions();

      const duration = Date.now() - startTime;
      
      const resultContext = {
        ...baseContext,
        duration,
        removedSessionsCount,
        remainingSessions: await this.getActiveSessionCount()
      };
            
      return {
        removedSessionsCount,
        remainingSessions: await this.getActiveSessionCount(),
        duration
      };
    } catch (error) {
      const duration = Date.now() - startTime;    
      throw error;
    }
  }
}

const sessionManager = new SessionManager();

logger.infoWithContext("SessionManager singleton created and exported", {
  component: "SessionManager",
  event: "singleton_export",
  instanceId: sessionManager._instanceId,
  timestamp: new Date().toISOString(),
  storageBackend: currentStorage?.store ? currentStorage.store.constructor.name : currentStorage.constructor.name
});

module.exports = {
  sessionManager,
  InMemorySessionStorage,
  setStorage,
  setExpressSessionStore,
  configureStorageFromConfig,
  createExpressSessionMiddleware,
  SESSION_CLEANUP_INTERVAL,
  SESSION_TOKEN_RETENTION_PERIOD
};