/**
 * RODiT Client Interface
 * Provides a clean API for interacting with RODiT services
 * 
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const roditManager = require('./lib/auth/roditmanager');
const stateManager = require('./lib/blockchain/statemanager');
const authMw = require('./lib/middleware/authenticationmw');
const { ensureProtocol } = require('./services/utils');
const { versionManager } = require('./services/versionmanager');
const nacl = require('tweetnacl');
const base64url = require('base64url');

// Import all SDK components that need to be accessible through RoditClient
const { 
  authenticate_apicall,
  login_client,
  logout_client,
  login_client_withnep413,
  login_portal,
  login_server,
  logout_server
} = require('./lib/middleware/authenticationmw');

const {
  validate_jwt_token_be,
  generate_jwt_token
} = require('./lib/auth/tokenservice');

const validatepermissions = require('./lib/middleware/validatepermissions');
const { sessionManager } = require('./lib/auth/sessionmanager');
const blockchainService = require('./lib/blockchain/blockchainservice');
const webhookHandler = require('./lib/middleware/webhookhandler');
const { versioningMiddleware } = require('./lib/middleware/versioningmw');
const { VersionManager } = require('./services/versionmanager');
const loggingmw = require('./lib/middleware/loggingmw');
const ratelimitmw = require('./lib/middleware/ratelimit');
const utils = require('./services/utils');
const config = require('./services/configsdk');
const performanceService = require('./services/performanceservice');

// Use the proper logger service
const logger = require('./services/logger');
// Avoid circular dependency - will require filecredentialsstore dynamically when needed


/**
 * RODiT Client Interface
 * Provides a clean API for interacting with RODiT services
 * 
 * @example
 * const { RoditClient } = require('@rodit/rodit-sdk');
 * const client = new RoditClient();
 * // Initialize the client
 * await client.init();
 */
class RoditClient {
  /**
   * Create a new RODiT client
   * @param {Object} [rcoptions] - Optional configuration
   * @param {string} [rcoptions.credentialsFilePath] - Path to credentials file
   * @param {boolean} [rcoptions.testMode] - Enable test mode for multiple instances
   */
  constructor(rcoptions = {}) {
    this.requestId = ulid();
    this.initialized = false;
    this.testMode = rcoptions.testMode || false;
    
    // Store configuration directly as instance properties
    this.credentialsFilePath = rcoptions.credentialsFilePath;
    // Set API version from config (env var), constructor option, or config default
    this.apiVersion = rcoptions.apiVersion || config.get('API_VERSION');
    
    // Create test instance of stateManager if in test mode
    if (this.testMode) {
      const { AuthStateManager } = require('./lib/blockchain/statemanager');
      this.stateManager = AuthStateManager.createTestInstance();
      logger.debug('Created test instance of stateManager', {
        component: 'RoditClient',
        method: 'constructor',
        requestId: this.requestId,
        testMode: true,
        stateManagerInstanceId: this.stateManager.instanceId
      });
    } else {
      // Use the singleton stateManager for normal operation
      this.stateManager = stateManager;
    }
    
    // Always configure version manager with the determined API version
    versionManager.setVersion(this.apiVersion);
    
    logger.debug('RODiT client instance created', {
      component: 'RoditClient',
      method: 'constructor',
      requestId: this.requestId,
      apiVersion: this.apiVersion,
      testMode: this.testMode,
      hasIndependentStateManager: this.testMode
    });
  }


  /**
   * Get configuration object
   * @returns {Object} Configuration object
   */
  getConfig() {
    return config;
  }

  /**
   * Get authentication middleware (clean syntax)
   * @returns {Function} Authentication middleware function
   */
  get authenticate() {
    return authenticate_apicall;
  }

  /**
   * Get permissions validation middleware (clean syntax)
   * @returns {Function} Permissions validation middleware function
   */
  get authorize() {
    return validatepermissions;
  }



  /**
   * Login client with NEP413
   * @param {Object} credentials - NEP413 credentials
   * @returns {Promise<Object>} Login result
   */
  async loginClientWithNEP413(credentials) {
    return login_client_withnep413(credentials);
  }

  /**
   * Validate JWT token
   * @param {string} token - JWT token to validate
   * @param {Object} vtoptions - Validation vtoptions
   * @returns {Promise<Object>} Validation result
   */
  async validateToken(token, vtoptions = {}) {
    return validate_jwt_token_be(token, vtoptions);
  }

  /**
   * Generate JWT token
   * @param {Object} payload - Token payload
   * @param {Object} gtoptions - Generation gtoptions
   * @returns {Promise<string>} Generated token
   */
  async generateToken(payload, gtoptions = {}) {
    return generate_jwt_token(payload, gtoptions);
  }

  /**
   * Get session manager instance
   * @returns {Object} Session manager
   */
  getSessionManager() {
    return sessionManager;
  }

  /**
   * Get session storage information
   * @returns {Object} Storage information including type and session count
   */
  async getSessionStorageInfo() {
    try {
      const storage = sessionManager.storage;
      const info = {
        storageType: storage.constructor?.name || 'UnknownStorage',
        sessionCount: await storage.size(),
        hasGetStorageInfo: typeof storage.getStorageInfo === 'function'
      };
      
      // If the storage has a getStorageInfo method (like InMemorySessionStorage), use it
      if (info.hasGetStorageInfo) {
        const detailedInfo = storage.getStorageInfo();
        return { ...info, ...detailedInfo };
      }
      
      return info;
    } catch (error) {
      logger.errorWithContext('Failed to get session storage info', {
        component: 'RoditClient',
        method: 'getSessionStorageInfo'
      }, error);
      
      return {
        storageType: 'Unknown',
        sessionCount: 0,
        error: error.message
      };
    }
  }

  /**
   * Get blockchain service instance
   * @returns {Object} Blockchain service
   */
  getBlockchainService() {
    return blockchainService;
  }

  /**
   * Get state manager instance
   * @returns {Object} State manager
   */
  getStateManager() {
    return this.stateManager;
  }

  /**
   * Get client state information
   * @returns {Object} Client state information
   */
  getClientState() {
    return {
      initialized: this.initialized,
      testMode: this.testMode,
      hasToken: !!this.jwt_token,
      sessionId: this.sessionId,
      apiEndpoint: this.apiendpoint,
      webhookUrl: this.webhookUrl,
      openApiUrl: this.openApiUrl,
      isTokenValid: this.isTokenValid(),
      isSubscriptionActive: this.isSubscriptionActive(),
      stateManagerId: this.stateManager?.instanceId || 'singleton'
    };
  }

  /**
   * Get webhook handler
   * @returns {Object} Webhook handler
   */
  getWebhookHandler() {
    return webhookHandler;
  }

  /**
   * Send webhook (backward compatibility alias)
   * @param {Object} data - Webhook payload object
   * @param {Object} [req] - Express request (for deriving peer webhook URL and headers)
   * @returns {Promise<Object>} Webhook result
   */
  async send_webhook(data, req) {
    return this.sendWebhook(data, req);
  }

  /**
   * Send webhook
   * @param {Object} data - Webhook payload object
   * @param {Object} [req] - Express request (optional)
   * @returns {Promise<Object>} Webhook result
   */
  async sendWebhook(data, req) {
    if (webhookHandler.send_webhook) {
      return webhookHandler.send_webhook(data, req);
    }
    throw new Error('Webhook functionality not available');
  }

  /**
   * Get versioning middleware
   * @returns {Function} Versioning middleware
   */
  getVersioningMiddleware() {
    return versioningMiddleware;
  }

  /**
   * Get version manager
   * @returns {Object} Version manager
   */
  getVersionManager() {
    return versionManager;
  }

  /**
   * Create new version manager instance
   * @returns {VersionManager} New version manager instance
   */
  createVersionManager() {
    return new VersionManager();
  }

  /**
   * Get logging middleware
   * @returns {Function} Logging middleware
   */
  getLoggingMiddleware() {
    return loggingmw;
  }

  /**
   * Get rate limit middleware
   * @returns {Function} Rate limit middleware
   */
  getRateLimitMiddleware() {
    return ratelimitmw;
  }

  /**
   * Get utilities
   * @returns {Object} Utilities object
   */
  getUtils() {
    return utils;
  }

  /**
   * Validate and set date
   * @param {*} value - Value to validate and set
   * @returns {Date} Validated date
   */
  validateAndSetDate(value) {
    return utils.validateAndSetDate(value);
  }

  /**
   * Validate and set JSON
   * @param {*} value - Value to validate and set
   * @returns {Object} Validated JSON object
   */
  validateAndSetJson(value) {
    return utils.validateAndSetJson(value);
  }

  /**
   * Validate and set URL
   * @param {*} value - Value to validate and set
   * @returns {string} Validated URL
   */
  validateAndSetUrl(value) {
    return utils.validateAndSetUrl(value);
  }

  /**
   * Calculate canonical hash
   * @param {*} data - Data to hash
   * @returns {string} Canonical hash
   */
  calculateCanonicalHash(data) {
    return utils.calculateCanonicalHash(data);
  }

  /**
   * Get logger instance
   * @returns {Object} Logger instance
   */
  getLogger() {
    return logger;
  }

  /**
   * Get performance service
   * @returns {Object} Performance service
   */
  getPerformanceService() {
    return performanceService;
  }

  /**
   * Get RODiT manager
   * @returns {Object} RODiT manager
   */
  getRoditManager() {
    return roditManager;
  }

  /**
   * Run manual cleanup on session manager
   * @param {...*} args - Arguments to pass to cleanup
   * @returns {Promise<*>} Cleanup result
   */
  async runManualCleanup(...args) {
    return sessionManager.runManualCleanup(...args);
  }

  /**
   * Initialize the RODiT client with configuration
   * @param {Object} [config] - Configuration overrides
   * @returns {Promise<boolean>} True if initialization was successful
   */
  async init(config = {}) {
    const requestId = this.requestId;
    
    try {
      // Update configuration from overrides
      if (config.credentialsFilePath) this.credentialsFilePath = config.credentialsFilePath;
      if (config.apiVersion) this.apiVersion = config.apiVersion;
      if (config.versionHeaderType) this.versionHeaderType = config.versionHeaderType;

      // Initialize the RODiT SDK first to load credentials from Vault
      // For test instances, we need to initialize configuration in the test instance's stateManager
      if (this.testMode) {
        // For test instances, initialize credentials store and config directly in the test stateManager
        await roditManager.initializeCredentialsStore();
        await roditManager.initializeRoditConfig(config.role || 'client', this.stateManager);
      } else {
        // For normal instances, use the standard initialization
        await roditManager.initializeRoditSdk(config);
      }

      // Get the loaded configuration
      const config_own_rodit = await this.stateManager.getConfigOwnRodit();
      if (!config_own_rodit) {
        throw new Error('Failed to load RODiT configuration from credentials store');
      }

      // Extract metadata and configure client
      this.roditMetadata = (config_own_rodit.own_rodit && config_own_rodit.own_rodit.metadata) || {};
      
      // Set API endpoint from metadata
      this.apiendpoint = ensureProtocol(this.roditMetadata.subjectuniqueidentifier_url);
      
      // Configure rate limiting
      if (this.roditMetadata.max_requests && this.roditMetadata.maxrq_window) {
        this.rateLimitState = {
          maxRequests: parseInt(this.roditMetadata.max_requests, 10),
          windowSeconds: parseInt(this.roditMetadata.maxrq_window, 10),
          requestCount: 0,
          windowStart: Date.now()
        };
      }
      
      // Parse JSON configuration fields
      this._parseJsonFields(requestId);

      // Configure optional URLs
      if (this.roditMetadata.openapijson_url) {
        this.openApiUrl = ensureProtocol(this.roditMetadata.openapijson_url);
      }

      if (this.roditMetadata.webhook_url) {
        this.webhookUrl = ensureProtocol(this.roditMetadata.webhook_url);
        this.webhookCidr = this.roditMetadata.webhook_cidr || '0.0.0.0/0';
      }

      this.initialized = true;
      
      logger.info('RODiT client initialized successfully', {
        component: 'RoditClient',
        method: 'init',
        requestId,
        endpoints: {
          api: this.apiendpoint,
          openApi: this.openApiUrl,
          webhook: this.webhookUrl
        }
      });
      
      return true;
    } catch (error) {
      logger.error('Failed to initialize RODiT client', {
        component: 'RoditClient',
        method: 'init',
        requestId,
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Parse JSON configuration fields
   * @private
   */
  _parseJsonFields(requestId) {
    try {
      if (this.roditMetadata.allowed_iso3166list) {
        this.allowedRegions = JSON.parse(this.roditMetadata.allowed_iso3166list);
      }
      
      if (this.roditMetadata.permissioned_routes) {
        this.permissionedRoutes = JSON.parse(this.roditMetadata.permissioned_routes);
      }
    } catch (parseError) {
      logger.warn('Failed to parse JSON metadata fields', {
        component: 'RoditClient',
        method: '_parseJsonFields',
        requestId,
        error: parseError.message
      });
    }
  }

  /**
   * Make an authenticated request to the API
   * @param {string} method - HTTP method
   * @param {string} path - API path
   * @param {Object} [data] - Request data
   * @param {Object} [roptions] - Additional roptions
   * @returns {Promise<Object>} API response
   */
  async request(method, path, data = null, roptions = {}) {
    if (!this.initialized) {
      throw new Error('Client not initialized. Call init() first.');
    }

    const requestId = ulid();
    
    // Check token validity before proceeding
    if (!this.isTokenValid()) {
      throw new Error('RODiT token is not valid at the current time');
    }
    
    // Check if the operation is permitted
    if (!this.isOperationPermitted(method, path)) {
      throw new Error(`Operation not permitted: ${method} ${path}`);
    }
    
    // Apply rate limiting if configured
    if (this.rateLimitState) {
      await this.applyRateLimit();
    }

    const url = new URL(path, this.apiendpoint).toString();
    const headers = {
      'Content-Type': 'application/json',
      'X-Request-ID': requestId,
      ...roptions.headers
    };
    
    // Apply API version headers
    const versionHeaders = versionManager.getVersionHeaders();
    Object.assign(headers, versionHeaders);

    // Get current session token
    const jwt_token = await this.getSessionToken();
    if (jwt_token) {
      headers['Authorization'] = `Bearer ${jwt_token}`;
    }

    const config = {
      method,
      headers,
      ...roptions
    };

    if (data) {
      config.body = JSON.stringify(data);
    }

    try {
      logger.debug('Making API request', {
        component: 'RoditClient',
        method: 'request',
        requestMethod: roptions.method || 'POST'
      });

      const response = await fetch(url, config);
      
      // Update rate limit counters
      if (this.rateLimitState) {
        this.rateLimitState.requestCount++;
      }
      
      // Handle rate limiting response headers if present
      if (response.headers.has('X-RateLimit-Remaining')) {
        const remaining = parseInt(response.headers.get('X-RateLimit-Remaining'), 10);
        const reset = parseInt(response.headers.get('X-RateLimit-Reset'), 10);
        
        logger.debug('Rate limit info from server', {
          component: 'RoditClient',
          method: 'request',
          requestId,
          rateLimitRemaining: remaining,
          rateLimitReset: reset
        });
      }

      const responseData = await response.json().catch(() => ({}));

      if (!response.ok) {
        // Handle specific error types
        if (response.status === 429) {
          throw new Error('Rate limit exceeded');
        } else if (response.status === 401) {
          // Token might be expired, try to refresh
          if (roptions.autoRefresh !== false) {
            logger.debug('Attempting to refresh authentication token', {
              component: 'RoditClient',
              method: 'request',
              requestId
            });
            
            await this.refreshToken();
            
            // Retry the request once with the new token
            return this.request(method, path, data, { ...roptions, autoRefresh: false });
          }
          throw new Error('Authentication failed');
        }
        
        throw new Error(responseData.message || `Request failed with status ${response.status}`);
      }

      return responseData;
    } catch (error) {
      logger.error('API request failed', {
        component: 'RoditClient',
        method: 'request',
        requestId,
        url,
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get current session token
   * @returns {Promise<string|null>} Current session token or null if not authenticated
   */
  async getSessionToken() {
    try {
      // Correctly retrieve the JWT token from the state manager
      return this.stateManager.getJwtToken();
    } catch (error) {
      logger.error('Failed to get session token from stateManager', {
        component: 'RoditClient',
        method: 'getSessionToken',
        requestId: this.requestId,
        error: error.message
      });
      return null;
    }
  }

  /**
   * Set authentication token
   * 
   * @param {string} token - Authentication token
   * @returns {boolean} Success indicator
   */
  async setSessionToken(token) {
    const requestId = ulid();
    
    logger.debug('Setting authentication token', {
      component: 'RoditClient',
      method: 'setSessionToken',
      requestId,
      hasToken: !!token
    });
    
    // Store token in AuthStateManager
    this.stateManager.setJwtToken(token);
    
    // Also cache locally for quick access
    this.jwt_token = token;
    
    return true;
  }
  
  /**
   * Set session data
   * 
   * @param {Object} sessionData - Session data
   * @returns {boolean} Success indicator
   */
  setSessionData(sessionData) {
    const requestId = ulid();
    
    logger.debug('Setting session data', {
      component: 'RoditClient',
      method: 'setSessionData',
      requestId,
      hasSessionData: !!sessionData,
      sessionId: sessionData?.id
    });
    
    this.sessionData = sessionData;
    
    return true;
  }
  
  /**
   * Get session data
   * 
   * @returns {Object|null} Session data or null if not set
   */
  getSessionData() {
    const requestId = ulid();
    
    logger.debug('Getting session data', {
      component: 'RoditClient',
      method: 'getSessionData',
      requestId,
      hasSessionData: !!this.sessionData,
      sessionId: this.sessionData?.id
    });
    
    return this.sessionData;
  }
  
  /**
   * Clear session data and token
   * 
   * @returns {boolean} Success indicator
   */
  clearSession() {
    const requestId = ulid();
    
    logger.debug('Clearing session data', {
      component: 'RoditClient',
      method: 'clearSession',
      requestId,
      hasSession: !!this.sessionData,
      sessionId: this.sessionData?.id
    });
    
    // Clear session data
    this.sessionData = null;
    this.jwt_token = null;
    
    // Also clear JWT token from stateManager
    this.stateManager.setJwtToken(null);
    
    return true;
  }
  
  
  /**
   * Create and initialize a new RODiT client in one step
   * @param {string|Object} [coptions] - Client role (string) or configuration coptions (object)
   * @returns {Promise<RoditClient>} Fully initialized client
   */
  static async create(coptions = {}) {
    // Handle string input for role
    const config = typeof coptions === 'string' ? { role: coptions } : coptions;
    const client = new RoditClient(config);
    await client.init(config);
    return client;
  }

  /**
   * Create a test instance of RODiT client with independent state
   * This is useful for testing multiple concurrent sessions
   * @param {Object} [ctioptions] - Client ctioptions
   * @returns {Promise<RoditClient>} Fully initialized test client
   */
  static async createTestInstance(ctioptions = {}) {
    const testOptions = {
      ...ctioptions,
      testMode: true
    };
    const client = new RoditClient(testOptions);
    await client.init(testOptions);
    return client;
  }


  
  /**
   * Handle Express login request (for server-side API endpoints)
   * Delegates to the authentication middleware's login_client function
   * 
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<void>}
   */
  async login_client(req, res) {
    logger.debug('Processing Express login request', {
      component: 'RoditClient',
      method: 'login_client',
      path: req.path,
      ip: req.ip
    });

    // Delegate directly to the authentication middleware's login_client function
    // The middleware handles all the logic including credential extraction, validation, and response
    return await login_client(req, res);
  }

  /**
   * Handle Express logout request (for server-side API endpoints)
   * Delegates to the authentication middleware's logout_client function
   * 
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<void>}
   */
  async logout_client(req, res) {
    logger.debug('Processing Express logout request', {
      component: 'RoditClient',
      method: 'logout_client',
      path: req.path,
      ip: req.ip
    });

    // Delegate directly to the authentication middleware's logout_client function
    // The middleware handles all the logic including session termination and response
    return await logout_client(req, res);
  }

  /**
   * Login to the RODiT API (for client-side usage)
   * 
   * @param {Object} lsoptions - Login lsoptions
   * @param {string} lsoptions.roditId - Optional RODiT to use for login
   * @returns {Promise<Object>} Login result with token
   */
  async login_server(lsoptions = {}) {
    const requestId = ulid();
    const startTime = Date.now();
    
    logger.debug('Starting login process', {
      component: 'RoditClient',
      method: 'login_server',
      requestId,
      lsoptions: {
        roditId: lsoptions.roditId || 'using default'
      }
    });
    
    try {
      // Get the RODiT configuration from the AuthStateManager instance
      const config_own_rodit = await this.stateManager.getConfigOwnRodit();
      
      if (!config_own_rodit) {
        logger.error('RODiT configuration not set in AuthStateManager', {
          component: 'RoditClient',
          method: 'login_server',
          requestId
        });
        throw new Error('RODiT configuration not set in AuthStateManager');
      }
      
      // Check if the config_own_rodit has a valid own_rodit property
      if (!config_own_rodit.own_rodit) {
        logger.error('Valid RODiT configuration not found in AuthStateManager', {
          component: 'RoditClient',
          method: 'login_server',
          requestId,
          configKeys: Object.keys(config_own_rodit)
        });
        throw new Error('Valid RODiT configuration not found in AuthStateManager');
      }
      
      logger.debug('Using login_server for authentication to ensure consistent mutual authentication', {
        component: 'RoditClient',
        method: 'login_server',
        requestId,
        roditId: config_own_rodit.own_rodit.token_id
      });
      
      // Use login_server directly to ensure consistent mutual authentication
      let loginResult;
      try {
        // Pass the entire config_own_rodit object to login_server
        loginResult = await authMw.login_server(config_own_rodit);
      } catch (error) {
        // Handle server connectivity issues
        const errorMessage = 'Unable to connect to authentication server. The server may be down or unreachable.';
        
        logger.error(errorMessage, {
          component: 'RoditClient',
          method: 'login_server',
          requestId,
          error: error.message,
          stack: error.stack
        });
        
        throw new Error(errorMessage);
      }
      
      // Check if login was successful
      if (loginResult.error) {
        logger.error('Login failed', {
          component: 'RoditClient',
          method: 'login_server',
          requestId,
          error: {
            message: 'Failed to login to server',
            details: loginResult.error
          },
          loginResult: JSON.stringify(loginResult)
        });
        
        // Add more detailed debugging information with safe property access
        logger.debug('Login result details', {
          component: 'RoditClient',
          method: 'login_server',
          requestId,
          apiEndpoint: config_own_rodit?.apiendpoint || 'unknown',
          roditId: config_own_rodit?.own_rodit?.token_id || 'unknown',
          hasPrivateKey: !!(config_own_rodit?.own_rodit_bytes_private_key)
        });
        
        // Provide a more informative error message
        let errorMessage = `Login failed: ${loginResult.error}`;
        
        // Add troubleshooting suggestions based on the error
        if (loginResult.error.includes('client')) {
          errorMessage += '. The authentication server may be down or experiencing issues. Please try again later or contact support.';
        } else if (loginResult.error.includes('credential') || loginResult.error.includes('authentication')) {
          errorMessage += '. Please check your RODiT credentials and try again.';
        }
        
        throw new Error(errorMessage);
      }
      
      // login_server returns jwt_token, not token
      if (loginResult.jwt_token) {
        this.jwt_token = loginResult.jwt_token;
        this.setSessionToken(loginResult.jwt_token);
        
        // Generate a session ID if not provided
        const sessionId = ulid();
        this.sessionId = sessionId;
        this.setSessionData({ 
          id: sessionId, 
          createdAt: Math.floor(Date.now() / 1000), 
          // Set default expiration to 1 hour from now
          expiresAt: Math.floor(Date.now() / 1000) + 3600, 
          status: 'active' 
        });
      }
      
      // Return success result
      const duration = Date.now() - startTime;
      logger.info('Login successful', {
        component: 'RoditClient',
        method: 'login_server',
        requestId,
        duration,
        roditId: config_own_rodit?.own_rodit?.token_id || 'unknown',
        hasToken: !!loginResult.jwt_token
      });
      
      // Track metric
      logger.metric && logger.metric('login_duration_ms', duration, {
        component: 'RoditClient',
        success: true
      });
      
      return {
        success: true,
        jwt_token: loginResult.jwt_token,
        sessionId: this.sessionId
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      
      logger.error('Login failed', {
        component: 'RoditClient',
        method: 'login_server',
        requestId,
        duration,
        error: {
          message: error.message,
          stack: error.stack
        }
      });
      
      // Track error metric
      logger.metric && logger.metric('login_duration_ms', duration, {
        component: 'RoditClient',
        success: false,
        error: error.name
      });
      
      logger.metric && logger.metric('login_errors', 1, {
        component: 'RoditClient',
        error: error.name
      });
      
      throw error;
    }
  }
  
  /**
   * Login to SignPortal for token signing operations
   * 
   * @param {Object} config_own_rodit - RODiT configuration object
   * @param {number} port - Portal port number
   * @returns {Promise<Object>} Login result with JWT token
   */
  async login_portal(config_own_rodit, port) {
    const requestId = ulid();
    const startTime = Date.now();
    
    logger.debug('Starting portal login process', {
      component: 'RoditClient',
      method: 'login_portal',
      requestId,
      port,
      roditId: config_own_rodit?.own_rodit?.token_id
    });
    
    try {
      // Delegate to the authentication middleware's login_portal function
      const loginResult = await login_portal(config_own_rodit, port);
      
      const duration = Date.now() - startTime;
      logger.info('Portal login successful', {
        component: 'RoditClient',
        method: 'login_portal',
        requestId,
        duration,
        hasToken: !!loginResult.jwt_token
      });
      
      // Track metric
      logger.metric && logger.metric('portal_login_duration_ms', duration, {
        component: 'RoditClient',
        success: true
      });
      
      return loginResult;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      
      logger.error('Portal login failed', {
        component: 'RoditClient',
        method: 'login_portal',
        requestId,
        duration,
        error: {
          message: error.message,
          name: error.name
        }
      });
      
      // Track error metric
      logger.metric && logger.metric('portal_login_duration_ms', duration, {
        component: 'RoditClient',
        success: false,
        error: error.name
      });
      
      throw error;
    }
  }
  
  /**
   * Logout from the RODiT API (for server-to-server usage)
   * Delegates to the authentication middleware's logout_server function
   * 
   * @returns {Promise<Object>} Logout result with termination token
   */
  async logout_server() {
    const requestId = ulid();
    const startTime = Date.now();
    
    logger.debug('Processing server logout request', {
      component: 'RoditClient',
      method: 'logout_server',
      requestId,
      hasToken: !!this.jwt_token,
      sessionId: this.sessionId
    });
    
    if (!this.jwt_token) {
      logger.warn('Logout called without an active token', {
        component: 'RoditClient',
        method: 'logout_server',
        requestId
      });
      return {
        success: false,
        error: 'No active token to logout',
        requestId
      };
    }
    
    try {
      // Delegate to the authentication middleware's logout_server function
      const logoutResult = await logout_server(this.jwt_token);
      
      // Clear local session data if logout was successful
      if (logoutResult.success) {
        this.jwt_token = null;
        this.sessionId = null;
        this.clearSession();
        
        const duration = Date.now() - startTime;
        logger.info('Server logout successful', {
          component: 'RoditClient',
          method: 'logout_server',
          requestId,
          duration,
          jwt_tokenInvalidated: logoutResult.jwt_tokenInvalidated,
          sessionClosed: logoutResult.sessionClosed,
          hasTerminationToken: !!logoutResult.terminationToken
        });
        
        // Track success metric
        logger.metric && logger.metric('logout_server_duration_ms', duration, {
          component: 'RoditClient',
          success: true
        });
      } else {
        logger.warn('Server logout failed, clearing local session anyway', {
          component: 'RoditClient',
          method: 'logout_server',
          requestId,
          error: logoutResult.error
        });
        
        // Clear local session even if server logout failed
        this.jwt_token = null;
        this.sessionId = null;
        this.clearSession();
      }
      
      return logoutResult;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      
      logger.error('Server logout failed', {
        component: 'RoditClient',
        method: 'logout_server',
        requestId,
        duration,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name
        }
      });
      
      // Track error metric
      logger.metric && logger.metric('logout_server_duration_ms', duration, {
        component: 'RoditClient',
        success: false,
        error: error.name
      });
      
      // Clear session data even if the logout call fails
      this.jwt_token = null;
      this.sessionId = null;
      this.clearSession();
      
      return {
        success: false,
        error: error.message,
        requestId
      };
    }
  }

  /**
   * Check if the client is authenticated
   * 
   * @returns {Promise<boolean>} True if the client is authenticated
   */
  async isAuthenticated() {
    const requestId = ulid();
    
    logger.debug('Checking authentication status', {
      component: 'RoditClient',
      method: 'isAuthenticated',
      requestId,
      hasToken: !!this.jwt_token,
      sessionId: this.sessionId
    });
    
    // If we don't have a token, we're definitely not authenticated
    if (!this.jwt_token) {
      logger.debug('No token available, client is not authenticated', {
        component: 'RoditClient',
        method: 'isAuthenticated',
        requestId
      });
      return false;
    }
    
    try {
      // Check if we have a valid session
      const sessionData = this.getSessionData();
      
      if (!sessionData) {
        logger.debug('No session data available, client is not authenticated', {
          component: 'RoditClient',
          method: 'isAuthenticated',
          requestId
        });
        return false;
      }
      
      // Check if the session has expired
      const currentTime = Math.floor(Date.now() / 1000);
      if (sessionData.expiresAt && sessionData.expiresAt < currentTime) {
        logger.debug('Session has expired', {
          component: 'RoditClient',
          method: 'isAuthenticated',
          requestId,
          sessionId: sessionData.id,
          expiresAt: sessionData.expiresAt,
          currentTime
        });
        return false;
      }
      
      // If we have a token and a valid non-expired session, we're authenticated
      logger.debug('Client is authenticated with valid token and session', {
        component: 'RoditClient',
        method: 'isAuthenticated',
        requestId,
        sessionId: sessionData.id,
        sessionStatus: sessionData.status
      });
      
      return true;
    } catch (error) {
      logger.error('Authentication check failed', {
        component: 'RoditClient',
        method: 'isAuthenticated',
        requestId,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name
        }
      });
      
      return false;
    }
  }
    
  /**
   * Check if the RODiT token is valid at the current time
   * @returns {boolean} True if the token is valid
   */
  isTokenValid() {
    if (!this.roditMetadata) {
      return false;
    }
    
    const now = new Date();
    let isValid = true;
    
    // Check not_before date if present
    if (this.roditMetadata.not_before) {
      const notBefore = new Date(this.roditMetadata.not_before);
      if (now < notBefore) {
        logger.debug('Token not yet valid', {
          component: 'RoditClient',
          method: 'isTokenValid',
          now: now.toISOString(),
          notBefore: notBefore.toISOString()
        });
        isValid = false;
      }
    }
    
    // Check not_after date if present
    if (this.roditMetadata.not_after) {
      const notAfter = new Date(this.roditMetadata.not_after);
      if (now > notAfter) {
        logger.debug('Token has expired', {
          component: 'RoditClient',
          method: 'isTokenValid',
          now: now.toISOString(),
          notAfter: notAfter.toISOString()
        });
        isValid = false;
      }
    }
    
    return isValid;
  }
  
  /**
   * Check if an operation is permitted based on permissioned_routes
   * @param {string} method - HTTP method
   * @param {string} path - API path
   * @returns {boolean} True if the operation is permitted
   */
  isOperationPermitted(method, path) {
    // If no permissioned routes are defined, allow all
    if (!this.permissionedRoutes) {
      return true;
    }
    
    try {
      // Check if the path matches any permissioned route
      const entities = this.permissionedRoutes.entities;
      if (!entities) {
        return true;
      }
      
      // Check if the method+path combination is in the permissioned routes
      const methods = entities.methods;
      if (!methods) {
        return true;
      }
      
      // If the path is explicitly listed, check its permission value
      if (methods[path]) {
        const permission = methods[path];
        // "+0" or any positive value indicates permission is granted
        return permission.startsWith('+');
      }
      
      // If not explicitly listed, check for wildcard patterns
      // This is a simplified implementation - could be enhanced with proper pattern matching
      const wildcardPaths = Object.keys(methods).filter(p => p.includes('*'));
      for (const wildcardPath of wildcardPaths) {
        const pattern = wildcardPath.replace('*', '.*');
        const regex = new RegExp(pattern);
        if (regex.test(path)) {
          const permission = methods[wildcardPath];
          return permission.startsWith('+');
        }
      }
      
      // Default to allowed if not explicitly denied
      return true;
    } catch (error) {
      logger.error('Error checking operation permission', {
        component: 'RoditClient',
        method: 'isOperationPermitted',
        error: error.message,
        path,
        httpMethod: method
      });
      // Default to allowed on error
      return true;
    }
  }
  
  /**
   * Get the complete RODiT configuration object
   * @returns {Promise<Object>} Complete RODiT configuration
   */
  async getConfigOwnRodit() {
    const requestId = ulid();
    
    logger.debug('Getting RODiT configuration', {
      component: 'RoditClient',
      method: 'getConfigOwnRodit',
      requestId,
      stateManagerExists: !!this.stateManager,
      stateManagerType: typeof this.stateManager
    });
    
    try {
      // Add detailed logging before the call
      logger.debug('Calling stateManager.getConfigOwnRodit()', {
        component: 'RoditClient',
        method: 'getConfigOwnRodit',
        requestId,
        stateManagerMethods: Object.getOwnPropertyNames(this.stateManager).filter(name => typeof this.stateManager[name] === 'function')
      });
      
      const config_own_rodit = await this.stateManager.getConfigOwnRodit();
      
      logger.debug('Retrieved RODiT configuration', {
        component: 'RoditClient',
        method: 'getConfigOwnRodit',
        requestId,
        hasConfig: !!config_own_rodit,
        hasOwnRodit: !!(config_own_rodit && config_own_rodit.own_rodit),
        configType: typeof config_own_rodit,
        configKeys: config_own_rodit ? Object.keys(config_own_rodit) : null,
        configStringified: config_own_rodit ? JSON.stringify(config_own_rodit, null, 2) : 'null'
      });
      
      return config_own_rodit;
    } catch (error) {
      logger.error('Failed to get RODiT configuration', {
        component: 'RoditClient',
        method: 'getConfigOwnRodit',
        requestId,
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get portal URL for SignPortal operations
   * @param {string} serviceProviderId - Service provider ID
   * @param {number} port - Portal port
   * @returns {string} Portal URL
   */
  getPortalUrl(serviceProviderId, port) {
    const requestId = ulid();
    
    logger.debug('Getting portal URL', {
      component: 'RoditClient',
      method: 'getPortalUrl',
      requestId,
      serviceProviderId,
      port
    });
    
    return stateManager.getPortalUrl(serviceProviderId, port);
  }

  /**
   * Get SignPortal JWT token
   * @returns {string|null} SignPortal JWT token
   */
  getSignPortalJwtToken() {
    const requestId = ulid();
    
    logger.debug('Getting SignPortal JWT token', {
      component: 'RoditClient',
      method: 'getSignPortalJwtToken',
      requestId
    });
    
    return stateManager.getSignPortalJwtToken();
  }

  /**
   * Set SignPortal JWT token
   * @param {string} token - SignPortal JWT token
   * @returns {Promise<string>} Set token
   */
  async setSignPortalJwtToken(token) {
    const requestId = ulid();
    
    logger.debug('Setting SignPortal JWT token', {
      component: 'RoditClient',
      method: 'setSignPortalJwtToken',
      requestId,
      hasToken: !!token
    });
    
    return await stateManager.setSignPortalJwtToken(token);
  }

  /**
   * Fetch with error handling for SignPortal operations
   * @param {string} url - URL to fetch
   * @param {Object} fwehspoptions - Fetch fwehspoptions
   * @returns {Promise<Object>} Response data
   */
  async fetchWithErrorHandlingSignPortal(url, fwehspoptions) {
    const requestId = ulid();
    
    logger.debug('Making SignPortal fetch request', {
      component: 'RoditClient',
      method: 'fetchWithErrorHandlingSignPortal',
      requestId,
      url,
      httpMethod: fwehspoptions?.method
    });
    
    return await stateManager.fetchWithErrorHandlingSignPortal(url, fwehspoptions);
  }
  
  /**
   * Checks if a subscription is active based on token metadata dates
   * @returns {boolean} True if subscription is active
   */
  isSubscriptionActive() {
    const config_own_rodit = this.stateManager.getConfigOwnRodit();
    
    if (!config_own_rodit?.own_rodit?.metadata) {
      return false;
    }
    
    const metadata = config_own_rodit.own_rodit.metadata;
    const now = new Date();
    let isActive = true;
    
    // Check not_before date if present
    if (metadata.not_before) {
      const notBefore = new Date(metadata.not_before);
      if (now < notBefore) {
        logger.debug('Subscription not yet active', {
          component: 'RoditClient',
          method: 'isSubscriptionActive',
          now: now.toISOString(),
          notBefore: notBefore.toISOString()
        });
        isActive = false;
      }
    }
    
    // Check not_after date if present
    if (metadata.not_after) {
      const notAfter = new Date(metadata.not_after);
      if (now > notAfter) {
        logger.debug('Subscription has expired', {
          component: 'RoditClient',
          method: 'isSubscriptionActive',
          now: now.toISOString(),
          notAfter: notAfter.toISOString()
        });
        isActive = false;
      }
    }
    
    return isActive;
  }

  /**
   * Apply rate limiting based on token configuration
   * @returns {Promise<void>}
   */
  async applyRateLimit() {
    if (!this.rateLimitState) {
      return;
    }
    
    const now = Date.now();
    const { maxRequests, windowSeconds, requestCount, windowStart } = this.rateLimitState;
    
    // Reset window if it has expired
    if (now - windowStart > windowSeconds * 1000) {
      this.rateLimitState.requestCount = 0;
      this.rateLimitState.windowStart = now;
      return;
    }
    
    // Check if we've exceeded the rate limit
    if (requestCount >= maxRequests) {
      const waitTime = windowStart + (windowSeconds * 1000) - now;
      
      logger.warn('Rate limit reached, waiting before next request', {
        component: 'RoditClient',
        method: 'applyRateLimit',
        waitTimeMs: waitTime,
        maxRequests,
        requestCount
      });
      
      // Wait until the window resets
      await new Promise(resolve => setTimeout(resolve, waitTime));
      
      // Reset the window
      this.rateLimitState.requestCount = 0;
      this.rateLimitState.windowStart = Date.now();
    }
  }
  
  /**
   * Refresh the authentication token
   * @returns {Promise<string>} New token
   */
  async refreshToken() {
    logger.debug('Refreshing authentication token', {
      component: 'RoditClient',
      method: 'refreshToken'
    });
    
    // Re-authenticate to get a fresh token
    await this.login_server();
    
    return this.getSessionToken();
  }
  
  /**
   * Register a webhook callback
   * @param {string} event_type - Event type to subscribe to
   * @param {string} callbackUrl - URL to receive webhook events
   * @returns {Promise<Object>} Registration result
   */
  async registerWebhook(event_type, callbackUrl) {
    if (!this.webhookUrl) {
      throw new Error('Webhook URL not configured in token metadata');
    }
    
    return this.request('POST', '/webhooks/register', {
      event_type,
      callback_url: callbackUrl
    });
  }
  
  /**
   * Unregister a webhook callback
   * @param {string} event_type - Event type to unsubscribe from
   * @param {string} callbackUrl - URL that was registered
   * @returns {Promise<Object>} Unregistration result
   */
  async unregisterWebhook(event_type, callbackUrl) {
    if (!this.webhookUrl) {
      throw new Error('Webhook URL not configured in token metadata');
    }
    
    return this.request('POST', '/webhooks/unregister', {
      event_type,
      callback_url: callbackUrl
    });
  }
  
  /**
   * Verify a webhook signature
   * @param {string} payload - Webhook payload
   * @param {string} signature - Webhook signature
   * @param {number} timestamp - Webhook timestamp
   * @returns {Promise<boolean>} True if signature is valid
   */
  async verifyWebhookSignature(payload, signature, timestamp) {
    try {
      // This is a placeholder - actual implementation would depend on the signature method
      // used by the webhook sender
      const crypto = require('crypto');
      const hmac = crypto.createHmac('sha256', await this.getWebhookSecret());
      
      hmac.update(`${timestamp}.${payload}`);
      const expectedSignature = hmac.digest('hex');
      
      return crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'hex'),
        Buffer.from(signature, 'hex')
      );
    } catch (error) {
      logger.error('Failed to verify webhook signature', {
        component: 'RoditClient',
        method: 'verifyWebhookSignature',
        error: error.message
      });
      return false;
    }
  }
}

// Export the RoditClient class and commonly used SDK components
module.exports = {
  RoditClient,
  // Core services needed by test modules and applications
  logger,
  stateManager,
  roditManager,
  sessionManager,
  blockchainService,
  utils,
  config,
  performanceService,
  authenticate_apicall,
  login_client,
  logout_client,
  login_client_withnep413,
  login_portal,
  login_server,
  logout_server,
  validate_jwt_token_be,
  generate_jwt_token,
  validatepermissions,
  webhookHandler,
  versioningMiddleware,
  loggingmw,
  ratelimitmw,
  versionManager,
  VersionManager,
  // Blockchain service functions
  nearorg_rpc_timestamp: blockchainService.nearorg_rpc_timestamp,
  /**
   * Derive public key (base64url) from a 32-byte Ed25519 private seed
   * @param {Uint8Array|Buffer} seedBytes
   * @returns {string} base64url-encoded public key
   */
  publicKeyFromSeedBase64url(seedBytes) {
    let bytes = seedBytes instanceof Uint8Array ? seedBytes : new Uint8Array(Buffer.from(seedBytes));
    // Accept 32-byte seed or 64-byte secretKey; normalize to 32-byte seed
    if (bytes.length === 64) {
      bytes = bytes.slice(0, 32);
    }
    if (bytes.length !== 32) {
      throw new Error('Invalid private key length: expected 32-byte seed or 64-byte secret key');
    }
    const kp = nacl.sign.keyPair.fromSeed(bytes);
    return base64url(Buffer.from(kp.publicKey));
  },
  /**
   * Sign arbitrary bytes with a 32-byte Ed25519 private seed, returning signature in base64url
   * @param {Uint8Array|Buffer} seedBytes
   * @param {Uint8Array|Buffer} dataBytes
   * @returns {string} base64url-encoded signature
   */
  signBytesBase64urlWithSeed(seedBytes, dataBytes) {
    const seed = seedBytes instanceof Uint8Array ? seedBytes : new Uint8Array(Buffer.from(seedBytes));
    const data = dataBytes instanceof Uint8Array ? dataBytes : new Uint8Array(Buffer.from(dataBytes));
    if (seed.length !== 32) {
      throw new Error('Invalid seed length: expected 32 bytes');
    }
    const kp = nacl.sign.keyPair.fromSeed(seed);
    const sig = nacl.sign.detached(data, kp.secretKey);
    return base64url(Buffer.from(sig));
  }
};