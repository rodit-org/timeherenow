/**
 * Configuration management
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

/*
 * SDK Config Wrapper with Fallback Defaults
 *
 * This module wraps the 'config' package to provide safe accessors that
 * gracefully fall back to baked-in defaults when config keys are missing.
 *
 * Exclusions: Vault keys (VAULT_*) and METHOD_PERMISSION_MAP are intentionally
 * NOT included in fallback defaults.
 */


// Attempt to load the 'config' package if present in the host app
let nodeConfig = null;
try {
  // Using require directly so consumer apps can bring their own 'config'
  // eslint-disable-next-line import/no-extraneous-dependencies
  nodeConfig = require("config");
} catch (_) {
  nodeConfig = null;
}

// Deep utilities (no external deps)
function deepGet(obj, keyPath) {
  if (!obj || !keyPath) return undefined;
  const parts = keyPath.split(".");
  let cur = obj;
  for (const p of parts) {
    if (cur && Object.prototype.hasOwnProperty.call(cur, p)) {
      cur = cur[p];
    } else {
      return undefined;
    }
  }
  return cur;
}

function isPlainObject(val) {
  return val && typeof val === "object" && !Array.isArray(val);
}

function deepMerge(target, source) {
  const out = Array.isArray(target) ? [...target] : { ...(target || {}) };
  if (isPlainObject(source)) {
    for (const [k, v] of Object.entries(source)) {
      if (isPlainObject(v)) {
        out[k] = deepMerge(out[k] || {}, v);
      } else if (Array.isArray(v)) {
        out[k] = Array.isArray(out[k]) ? [...out[k], ...v] : [...v];
      } else {
        out[k] = v;
      }
    }
  }
  return out;
}

// Baked-in fallback defaults sourced from config/default.json (excluding Vault and METHOD_PERMISSION_MAP)
const FALLBACK_DEFAULTS = {
  API_VERSION: "0.0.0",
  RODIT_NEAR_CREDENTIALS_SOURCE: "env",
  SECURITY_OPTIONS: {
    LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY: "0.80",
    THRESHOLD_VALIDATION_TYPE: "0.10",
    DURATIONRAMP: "0.85",
    SERVERORCLIENT: "SERVER-INITIATED",
    SILENT_LOGIN_FAILURES: false,
  },
  // Default to env-based credential store; host apps can override with RODIT_NEAR_CREDENTIALS_SOURCE env
  credentials: {
    filePath: "./.near-credentials/credentials-not-set.json"
  },
  API_DEFAULT_OPTIONS: {
    ISO639: "es",
    ISO3166: "ES",
    ISO15924: "215",
    TIMESTAMP_MAX_AGE: 300,
    TIMEOPTIONS: {
      tzname: "Europe/Madrid",
      tzoffset: "+01:00",
      datetimeformat: "2023-04-15T14:30:00-05:00",
    },
    LOG_DIR: "./log-directory-not-set",
  },
  // Performance monitoring configuration
  PERFORMANCE: {
    LOAD_LEVELS: {
      LOW: 'low',
      MEDIUM: 'medium',
      HIGH: 'high',
      CRITICAL: 'critical'
    },
    LOAD_THRESHOLDS: {
      MEDIUM: 500,   // >500 req/min = medium load
      HIGH: 1000,    // >1000 req/min = high load
      CRITICAL: 2000 // >2000 req/min = critical load
    }
  },
  NEAR_RPC_URL: "https://rpc.testnet.fastnear.com",
  NEAR_CONTRACT_ID: "rodit-org.near",
  SERVICE_NAME: "service-name-not-set",
  NODE_ENV: "production", // Environment: production, development, test
  LOG_LEVEL: "info", // Logging verbosity: error, warn, info, debug, trace
  // Session storage configuration
  SESSION_STORAGE_TYPE: "memory",
  // Session cleanup configuration
  SESSION_CLEANUP_INTERVAL: 500000, // Milliseconds
  SESSION_TOKEN_RETENTION_PERIOD: 5000000,  // Seconds
  NEAR_CACHE_TTLS: 5000, // Milliseconds
  // Token validation cache TTL (milliseconds) - trades security for performance
  // Lower values = more secure but more storage lookups
  // Higher values = faster but longer window after logout where token may still work
  // Set to 0 to disable caching (always check session state)
  TOKEN_VALIDATION_CACHE_TTL: 5000, // 5 seconds default
  // Default empty permission map so consumers can opt-into permissions as needed
  METHOD_PERMISSION_MAP: {},
};

function has(pathStr) {
  if (nodeConfig && typeof nodeConfig.has === "function") {
    try {
      if (nodeConfig.has(pathStr)) return true;
    } catch (_) {}
  }
  return deepGet(FALLBACK_DEFAULTS, pathStr) !== undefined;
}

/**
 * Get configuration value with fallback support
 * @param {string} pathStr - Configuration key path (e.g., 'API_DEFAULT_OPTIONS.LOG_DIR')
 * @param {*} defaultValue - Optional default value if key is missing
 * @returns {*} Configuration value
 */
function get(pathStr, defaultValue) {
  let hostValue;
  let hostHasValue = false;
  
  // First try to get from host config
  if (nodeConfig) {
    try {
      hostValue = nodeConfig.get(pathStr);
      hostHasValue = true;
    } catch (err) {
      // Host config doesn't have this key, continue to fallback
    }
  }
  
  // If host has the value, return it
  if (hostHasValue) {
    return hostValue;
  }
  
  // Try fallback defaults
  const fallbackValue = deepGet(FALLBACK_DEFAULTS, pathStr);
  if (fallbackValue !== undefined) {
    return fallbackValue;
  }
  
  // If default value provided, return it
  if (defaultValue !== undefined) {
    return defaultValue;
  }
  
  // Throw error similar to config package
  const err = new Error(`Configuration property '${pathStr}' is not defined`);
  err.code = 'CONFIG_PROPERTY_MISSING';
  throw err;
}

function getAllMerged() {
  // Returns a merged view: node config (if any) overlaid onto fallbacks
  let merged = { ...FALLBACK_DEFAULTS };
  if (nodeConfig && typeof nodeConfig.util?.toObject === "function") {
    try {
      const asObject = nodeConfig.util.toObject();
      merged = deepMerge(FALLBACK_DEFAULTS, asObject);
    } catch (_) {}
  }
  return merged;
}

module.exports = {
  has,
  get,
  getAllMerged,
  FALLBACK_DEFAULTS,
};
