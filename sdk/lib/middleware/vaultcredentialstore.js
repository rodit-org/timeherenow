/**
 * Vault-based credential storage
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const config = require('../../services/configsdk');
const { ulid } = require("ulid");
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const { validateAndExtractCredentials } = require("../../services/utils");

logger.debugWithContext("Loading vaultcredentialstore.js module", createLogContext(
  "ModuleLoader",
  "moduleInitialization",
  {
    module: "vaultcredentialstore.js",
    loadedAt: new Date().toISOString()
  }
));

class ProductionVaultManager {
  constructor() {
    this.vault = require("node-vault")();
    this.vault.endpoint = config.get("VAULT_ENDPOINT");
    this.vault.apiVersion = "v1";
    this.roleId = config.get("VAULT_ROLE_ID");
    this.secretId = config.get("VAULT_SECRET_ID");
    this.renewalInterval = 60 * 60 * 1000; // 1 hour in milliseconds
    this.vaultInitialized = false;
    this.vaultPath = null;
    this.credentials = {};
  }

  async getProductionVaultToken() {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "CredentialManager",
      "getProductionVaultToken",
      { requestId }
    );
    
    logger.infoWithContext("Attempting Vault authentication", {
      ...baseContext,
      result: 'call',
      reason: 'Vault authentication requested'
    });
    
    try {
      const result = await this.vault.approleLogin({
        role_id: this.roleId,
        secret_id: this.secretId,
      });
      
      logger.infoWithContext("Vault authentication successful", {
        ...baseContext,
        duration: Date.now() - startTime,
        result: 'success',
        reason: 'Vault authentication succeeded'
      });
      logger.metric("vault_authentication_duration_ms", Date.now() - startTime, {
        component: "CredentialManager",
        result: 'success',
        reason: 'Vault authentication succeeded'
      });
      
      return result.auth.client_token;
    } catch (error) {
      logger.metric("vault_authentication_duration_ms", Date.now() - startTime, {
        component: "CredentialManager",
        result: 'failure',
        reason: error.message || 'Vault authentication failed'
      });
      logErrorWithMetrics(
        "Error authenticating with Vault", 
        {
          ...baseContext,
          duration: Date.now() - startTime,
          result: 'failure',
          reason: error.message || 'Vault authentication failed'
        },
        error,
        "vault_authentication_error",
        { error_type: "auth_failure" }
      );
      throw new Error("Error 108: Vault authentication failed");
    }
  }

  async initialize() {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext('CredentialManager', 'initialize', { requestId });
    const log = (message, extra = {}) => logger.infoWithContext(message, { ...baseContext, ...extra });
    const logError = (error, context = {}) => logErrorWithMetrics(
      error.message, 
      { ...baseContext, ...context, result: 'failure' },
      error,
      'vault_initialization_error',
      { error_type: error.errorType || 'initialization_failure' }
    );

    log('Starting vault initialization', { result: 'call', reason: 'Vault initialization requested' });

    if (this.vaultInitialized) {
      log('Vault already initialized', { 
        duration: Date.now() - startTime,
        result: 'success',
        reason: 'Vault was already initialized' 
      });
      return this.vault;
    }

    try {
      // Initialize Vault token
      this.vault.token = await this.getProductionVaultToken();
      log('Checking Vault health status', { result: 'call', reason: 'Vault health status check requested' });
      
      // Check Vault health
      const health = await this.vault.health();
      
      if (!health.initialized || health.sealed) {
        const error = new Error(health.sealed ? 'Error 110: Vault is sealed' : 'Error 109: Vault is not initialized');
        error.errorType = health.sealed ? 'sealed' : 'not_initialized';
        throw error;
      }

      // Load and validate config
      if (!config || typeof config.get !== 'function') {
        const error = new Error('Config object is not properly initialized');
        error.errorType = 'config_initialization_error';
        throw error;
      }

      this.vaultPath = config.get('VAULT_RODIT_KEYVALUE_PATH');
      log('Retrieved vault path from config', { 
        vaultPath: this.vaultPath, 
        result: 'success', 
        reason: 'Vault path retrieved from config' 
      });

      this.vaultInitialized = true;
      const duration = Date.now() - startTime;
      
      log('Vault initialized successfully', { 
        vaultInitialized: true,
        vaultPath: this.vaultPath,
        duration,
        result: 'success',
        reason: 'Vault initialized successfully' 
      });

      logger.metric('vault_initialization_duration_ms', duration, {
        component: 'CredentialManager',
        result: 'success',
        reason: 'Vault initialized successfully'
      });

      return this.vault;
    } catch (error) {
      const duration = Date.now() - startTime;
      this.vaultInitialized = false;
      
      logError(error, { 
        duration, 
        reason: error.message || 'Vault initialization failed',
        errorType: error.code || 'UNKNOWN_ERROR'
      });
      
      logger.metric('vault_initialization_duration_ms', duration, {
        component: 'CredentialManager',
        result: 'failure',
        reason: error.message || 'Vault initialization failed',
        errorType: error.code || 'UNKNOWN_ERROR'
      });
      
      logger.metric('vault_initialization_errors_total', 1, {
        component: 'CredentialManager',
        errorType: error.code || 'UNKNOWN_ERROR'
      });

      throw error;
    }
  }

  async setupTokenRenewal() {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "CredentialManager",
      "setupTokenRenewal",
      { requestId }
    );
    
    logger.debugWithContext("Starting token renewal setup", baseContext);
    
    try {
      // Get token info to determine TTL
      const tokenInfo = await this.vault.tokenLookupSelf();
      const ttlSeconds = tokenInfo.data.ttl;
      
      // Calculate renewal time (renew at 80% of TTL)
      const renewalTimeMs = (ttlSeconds * 0.8) * 1000;
      
      logger.infoWithContext("Setting up token renewal", {
        ...baseContext,
        ttlSeconds,
        renewalIntervalMs: renewalTimeMs || this.renewalInterval,
        nextRenewalAt: new Date(Date.now() + (renewalTimeMs || this.renewalInterval)).toISOString(),
        duration: Date.now() - startTime
      });
      
      const interval = renewalTimeMs || this.renewalInterval;
      
      setInterval(async () => {
        const renewalRequestId = ulid();
        const renewalStartTime = Date.now();
        
        // Create a context for the renewal operation
        const renewalContext = createLogContext(
          "CredentialManager",
          "tokenRenewal",
          { requestId: renewalRequestId }
        );
        
        logger.debugWithContext("Attempting to renew Vault token", renewalContext);
        
        try {
          // Use proper token renewal instead of re-authenticating
          const renewResponse = await this.vault.tokenRenew();
          
          logger.infoWithContext("Successfully renewed Vault token", {
            ...renewalContext,
            newTtl: renewResponse.auth?.lease_duration || "unknown",
            duration: Date.now() - renewalStartTime
          });
          
          // Add metrics for successful renewal
          logger.metric("vault_token_renewal_duration_ms", Date.now() - renewalStartTime, {
            success: true,
            component: "CredentialManager"
          });
        } catch (error) {
          logErrorWithMetrics(
            "Error renewing Vault token, attempting re-authentication", 
            {
              ...renewalContext,
              duration: Date.now() - renewalStartTime
            },
            error,
            "vault_token_renewal_error",
            { error_type: "renewal_failure" }
          );
          
          try {
            const token = await this.getProductionVaultToken();
            this.vault.token = token;
            
            logger.infoWithContext("Successfully re-authenticated with Vault", {
              ...renewalContext,
              duration: Date.now() - renewalStartTime
            });
            
            // Add metrics for successful re-authentication
            logger.metric("vault_token_reauthentication_duration_ms", Date.now() - renewalStartTime, {
              success: true,
              component: "CredentialManager"
            });
          } catch (reAuthError) {
            logErrorWithMetrics(
              "Failed to re-authenticate with Vault", 
              {
                ...renewalContext,
                duration: Date.now() - renewalStartTime
              },
              reAuthError,
              "vault_token_reauthentication_error",
              { error_type: "reauthentication_failure" }
            );
          }
        }
      }, interval);
      
      return true;
    } catch (error) {
      logErrorWithMetrics(
        "Error setting up token renewal", 
        {
          ...baseContext,
          duration: Date.now() - startTime
        },
        error,
        "vault_token_renewal_setup_error",
        { error_type: "setup_failure" }
      );
      return false;
    }
  }

  async getRoditFromVault(vaultPath, secretKey) {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "CredentialManager",
      "getRoditFromVault",
      { 
        requestId,
        vaultPath,
        secretKey 
      }
    );
    
    this.validateVaultParameters(vaultPath, secretKey);

    try {
      logger.debugWithContext("Retrieving data from Vault", {
        ...baseContext,
        path: `secret/data/${vaultPath}`,
        apiEndpoint: this.vault.endpoint,
        hasToken: !!this.vault.token
      });
      
      const result = await this.vault.read(`secret/data/${vaultPath}`);
      const secretData = result.data.data[secretKey];

      if (!secretData) {
        const error = new Error(
          `Error 048: No data found for ${secretKey} at secret/data/${vaultPath}`
        );
        
        logErrorWithMetrics(
          "No data found in Vault path", 
          baseContext,
          error,
          "vault_data_retrieval_error",
          { error_type: "data_not_found" }
        );
        
        throw error;
      }

      logger.debugWithContext("Successfully retrieved data from Vault", {
        ...baseContext,
        duration: Date.now() - startTime
      });
      
      const parsedData = this.parseSecretData(secretData, secretKey);
      return validateAndExtractCredentials(parsedData, logger);
    } catch (error) {
      logErrorWithMetrics(
        "Error retrieving Rodit config from Vault", 
        {
          ...baseContext,
          duration: Date.now() - startTime,
          errorDetails: error.response?.data || error.response || "No details available",
          statusCode: error.response?.statusCode
        },
        error,
        "vault_data_retrieval_error",
        { error_type: "retrieval_failure" }
      );
      throw error;
    }
  }

  validateVaultParameters(vaultPath, secretKey) {
    const requestId = ulid();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "CredentialManager",
      "validateVaultParameters",
      { 
        requestId,
        vaultPath,
        secretKey 
      }
    );
    
    logger.debugWithContext("Validating Vault parameters", baseContext);
    
    if (!this.vault || typeof this.vault.read !== "function") {
      const error = new Error("Error 051: Invalid vault object");
      logErrorWithMetrics(
        "Invalid vault object", 
        baseContext,
        error,
        "vault_parameter_validation_error",
        { error_type: "invalid_vault" }
      );
      throw error;
    }
    if (!vaultPath || typeof vaultPath !== "string") {
      const error = new Error("Error 052: Invalid VAULT_RODIT_KEYVALUE_PATH");
      logErrorWithMetrics(
        "Invalid vault path", 
        baseContext,
        error,
        "vault_parameter_validation_error",
        { error_type: "invalid_path" }
      );
      throw error;
    }
    if (!secretKey || typeof secretKey !== "string") {
      const error = new Error("Error 047: Invalid or missing secretKey parameter");
      logErrorWithMetrics(
        "Invalid secret key", 
        baseContext,
        error,
        "vault_parameter_validation_error",
        { error_type: "invalid_key" }
      );
      throw error;
    }
    
    logger.debugWithContext("Vault parameters validated successfully", baseContext);
  }

  parseSecretData(secretData, secretKey) {
    const requestId = ulid();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "CredentialManager",
      "parseSecretData",
      { 
        requestId,
        secretKey,
        dataType: typeof secretData
      }
    );
    
    logger.debugWithContext("Parsing secret data", baseContext);
    
    if (typeof secretData === "string") {
      try {
        const parsedData = JSON.parse(secretData);
        logger.debugWithContext("Successfully parsed secret data", baseContext);
        return parsedData;
      } catch (parseError) {
        const error = new Error(`Error 046: Invalid JSON format in ${secretKey}`);
        logErrorWithMetrics(
          "Failed to parse secret data", 
          baseContext,
          parseError,
          "vault_data_parsing_error",
          { error_type: "invalid_json" }
        );
        throw error;
      }
    }
    
    logger.debugWithContext("Secret data already in object format", baseContext);
    return secretData;
  }

  async getCredentials(type) {
    const requestId = ulid();
    const startTime = Date.now();
    const maxRetries = 2; // Maximum number of retry attempts
    let retryCount = 0;
    let lastError = null;
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "CredentialManager",
      "getCredentials",
      { 
        requestId,
        credentialType: type
      }
    );

    logger.debugWithContext("Retrieving credentials", baseContext);

    // Use cached credentials if available
    if (this.credentials[type]) {
      logger.debugWithContext("Using cached credentials", baseContext);
      return this.credentials[type];
    }

    // Make sure vault is initialized
    if (!this.vaultInitialized) {
      logger.debugWithContext("Vault not initialized, initializing now", baseContext);
      await this.initialize();
    }

    // Retry logic for vault operations
    while (retryCount <= maxRetries) {
      try {
        // Make the accountType consistent with the type parameter
        const accountType = `account_${type}`;
        const vaultPath = `${this.vaultPath}/${type}`;

        logger.debugWithContext("Fetching credentials from vault", {
          ...baseContext,
          vaultPath,
          attempt: retryCount + 1,
          maxAttempts: maxRetries + 1
        });

        const vaultData = await this.getRoditFromVault(
          vaultPath,
          accountType
        );

        // Add detailed logging about the vault data received
        logger.debugWithContext("Vault data received", {
          ...baseContext,
          hasVaultData: !!vaultData,
          dataKeys: vaultData ? Object.keys(vaultData) : [],
          hasPrivateKey: vaultData && !!vaultData.private_key
        });

        // Safely check for private_key before using it
        if (!vaultData || !vaultData.private_key || typeof vaultData.private_key !== "string") {
          const error = new Error(`Invalid or missing private_key for ${type}`);
          logErrorWithMetrics(
            "Invalid private key format", 
            baseContext,
            error,
            "credential_retrieval_error",
            { error_type: "invalid_private_key" }
          );
          throw error;
        }

        // Cache the credentials for future use
        this.credentials[type] = vaultData;
        
        const duration = Date.now() - startTime;
        logger.infoWithContext("Successfully retrieved credentials", {
          ...baseContext,
          duration,
          accountId: vaultData.account_id // Safe to log account ID
        });

        // Emit metrics for dashboards
        logger.metric("credential_retrieval_duration_ms", duration, {
          success: true,
          credentialType: type,
          component: "CredentialManager"
        });

        return vaultData;
      } catch (error) {
        lastError = error;
        
        // Log the error but don't throw yet if we have retries left
        const isRetrying = retryCount < maxRetries;
        const duration = Date.now() - startTime;
        
        if (isRetrying) {
          logger.warnWithContext(`Retryable error retrieving credentials`, {
            ...baseContext,
            duration,
            errorMessage: error.message,
            errorCode: error.code || "UNKNOWN_ERROR",
            attempt: retryCount + 1,
            willRetry: true
          });
          
          // Emit metrics for dashboards
          logger.metric("credential_retrieval_duration_ms", duration, {
            success: false,
            credentialType: type,
            errorType: error.code || "UNKNOWN_ERROR",
            component: "CredentialManager",
            retryAttempt: retryCount
          });
          
          retryCount++;
          await new Promise(resolve => setTimeout(resolve, 1000 * retryCount)); // Exponential backoff
          continue;
        }
        
        // If we've exhausted retries, log and throw the last error
        logErrorWithMetrics(
          "Failed to retrieve credentials after all retry attempts", 
          {
            ...baseContext,
            duration,
            attempts: retryCount + 1,
            maxAttempts: maxRetries + 1
          },
          lastError,
          "credential_retrieval_error",
          { error_type: "max_retries_exceeded" }
        );
        
        // Emit metrics for dashboards
        logger.metric("credential_retrieval_errors_total", 1, {
          credentialType: type,
          errorType: error.code || "UNKNOWN_ERROR",
          component: "CredentialManager"
        });
        
        throw lastError;
      }
    }
  }
}

const vaultManager = new ProductionVaultManager();

module.exports = {
  initializeProductionCredentialStore: () => vaultManager.initialize(),
  setupTokenRenewal: () => vaultManager.setupTokenRenewal(),
  getCredentials: (type) => vaultManager.getCredentials(type),
  vault: vaultManager.vault,
};
