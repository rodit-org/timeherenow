/**
 * RODIT manager for handling RODIT-specific operations
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const config = require("../../services/configsdk");
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
// Dynamically select credential store based on config/env (flat key only)
const RODIT_NEAR_CREDENTIALS_SOURCE = config.get("RODIT_NEAR_CREDENTIALS_SOURCE");
logger.debugWithContext(
  "Selecting credential store",
  createLogContext("RoditManager", "credentialStoreSelect", {
    source: RODIT_NEAR_CREDENTIALS_SOURCE,
  })
);

let credentialStoreModule;
if (RODIT_NEAR_CREDENTIALS_SOURCE === "file") {
  credentialStoreModule = require("../middleware/filecredentialstore");
} else if (RODIT_NEAR_CREDENTIALS_SOURCE === "env") {
  credentialStoreModule = require("../middleware/environcredentialstore");
} else {
  credentialStoreModule = require("../middleware/vaultcredentialstore");
}

// const credentialStoreModule = require("../middleware/filecredentialstore");

const {
  initializeProductionCredentialStore,
  setupTokenRenewal,
  getCredentials,
  vault,
} = credentialStoreModule;
const {
  nearorg_rpc_state,
  nearorg_rpc_tokensfromaccountid,
} = require("../blockchain/blockchainservice");
const stateManager = require("../blockchain/statemanager");

const baseModuleContext = createLogContext("ModuleLoader", "RoditManager", {
  loadedAt: new Date().toISOString(),
});

logger.debugWithContext("Loading roditmanager.js module", baseModuleContext);
/**
 * RoditManager class
 * Singleton class for managing RODiT configurations and credentials
 */
class RoditManager {
  constructor() {
    const instanceId = ulid();

    const constructorContext = createLogContext("RoditManager", "constructor", {
      instanceId,
      hasExistingInstance: !!RoditManager.instance,
      existingInstanceId: RoditManager.instance
        ? RoditManager.instance._instanceId
        : null,
    });

    logger.debugWithContext(
      "RoditManager constructor called",
      constructorContext
    );
    if (RoditManager.instance) {
      logger.debugWithContext("Returning existing RoditManager instance", {
        ...constructorContext,
        instanceId: RoditManager.instance._instanceId,
      });
      return RoditManager.instance;
    }

    this._instanceId = instanceId; // Store the instance ID
    logger.debug("Creating new RoditManager instance", {
      component: "RoditManager",
      instanceId: this._instanceId,
    });

    this.stateManager = stateManager;

    RoditManager.instance = this;
  }

  async initializeCredentialsStore() {
    const requestId = ulid();

    logger.debug("Initializing CredentialManager", {
      component: "RoditManager",
      method: "initializeCredentialsStore",
      requestId,
      instanceId: this._instanceId,
    });

    try {
      const credentialstoreInstance =
        await initializeProductionCredentialStore();
      await setupTokenRenewal(credentialstoreInstance);

      logger.debug(
        "CredentialStore initialization completed through CredentialManager",
        {
          component: "RoditManager",
          method: "initializeCredentialsStore",
          requestId,
          instanceId: this._instanceId,
        }
      );

      return credentialstoreInstance;
    } catch (error) {
      logger.error("Error during CredentialStore initialization", {
        component: "RoditManager",
        method: "initializeCredentialsStore",
        requestId,
        errorMessage: error.message,
        errorCode: error.code || "UNKNOWN_ERROR",
        stack: error.stack,
      });

      throw error;
    }
  }

  async initializeRoditConfig(type, targetStateManager = null) {
    const requestId = ulid();
    const startTime = Date.now();

    // Use the provided stateManager or fall back to the singleton
    const stateManagerToUse = targetStateManager || this.stateManager;

    // Create a base context for this method
    const baseContext = createLogContext(
      "RoditManager",
      "initializeRoditConfig",
      {
        requestId,
        configType: type,
        usingTestStateManager: !!targetStateManager,
      }
    );

    logger.infoWithContext("Starting RODiT config initialization", baseContext);

    try {
      logger.debugWithContext("Getting credentials", {
        ...baseContext,
        step: "fetchCredentials",
      });

      let credentials = await getCredentials(type);

      if (!credentials) {
        logErrorWithMetrics({
          error: new Error(`Credentials not available for ${type}`),
          context: {
            ...baseContext,
            step: "credentialCheck",
          },
          metrics: [
            {
              name: "credential_retrieval_failures",
              value: 1,
              tags: { configType: type },
            },
          ],
        });
        throw new Error(`Credentials not available for ${type}`);
      }

      // Handle case where credentials might be in an object with account_id as key
      if (
        typeof credentials === "object" &&
        Object.keys(credentials).length === 1
      ) {
        credentials = Object.values(credentials)[0];
      }

      // Require implicit_account_id
      const account_id = credentials.implicit_account_id;
      if (!account_id) {
        throw new Error("Credentials must contain implicit_account_id");
      }

      logger.infoWithContext("Using account for initialization", {
        ...baseContext,
        accountId: account_id,
        step: "accountSetup",
      });

      logger.debugWithContext("Checking account state on blockchain", {
        ...baseContext,
        accountId: account_id,
        step: "blockchainCheck",
      });

      const accountState = await nearorg_rpc_state(account_id);

      if (!accountState) {
        logger.warnWithContext("Account has no balance in network", {
          ...baseContext,
          accountId: account_id,
          step: "blockchainCheck",
        });
      } else {
        logger.infoWithContext("Account state verified on blockchain", {
          ...baseContext,
          accountId: account_id,
          step: "blockchainCheck",
        });
      }

      logger.debugWithContext("Fetching RODiT tokens for account", {
        ...baseContext,
        accountId: account_id,
        step: "tokenFetch",
      });

      const own_rodit = await nearorg_rpc_tokensfromaccountid(account_id);

      // Check if we have a real RODiT token
      if (!own_rodit || !own_rodit.token_id) {
        logger.warnWithContext(
          "No RODiT instances found, proceeding with partial initialization",
          {
            ...baseContext,
            accountId: account_id,
            step: "tokenCheck",
          }
        );

        // Create a minimal configuration for signroot
        const minimalConfig = {
          own_rodit: {
            token_id: "",
            owner_id: account_id,
            metadata: {
              subjectuniqueidentifier_url: "api-url-not-set.example.com",
              serviceprovider_id: "",
              not_after: "2030-01-01",
              not_before: "2020-01-01",
            },
          },
          own_rodit_bytes_private_key: credentials.signing_bytes_key,
          apiEndpoint: "localhost",
          port: "",
          iso639: config.get("API_DEFAULT_OPTIONS.ISO639"),
          iso3166: config.get("API_DEFAULT_OPTIONS.ISO3166"),
          iso15924: config.get("API_DEFAULT_OPTIONS.ISO15924"),
          timeoptions: config.get("API_DEFAULT_OPTIONS.TIMEOPTIONS"),
          tokenrenewaloptions: config.get("SECURITY_OPTIONS"),
        };

        await stateManagerToUse.setConfigOwnRodit(minimalConfig);

        const session_base64url_jwk_public_key = Buffer.from(
          account_id,
          "hex"
        ).toString("base64url");

        logger.debugWithContext("Converting implicit account ID to base64url", {
          ...baseContext,
          step: "keyConversion",
        });

        logger.debugWithContext("Setting session base64url JWK public key", {
          ...baseContext,
          step: "setSessionKey",
        });

        await stateManagerToUse.setOwnBase64urlJwkPublicKey(
          session_base64url_jwk_public_key
        );

        const duration = Date.now() - startTime;
        logger.infoWithContext(
          "RODiT config initialized with minimal configuration",
          {
            ...baseContext,
            duration,
            configLevel: "partial",
            step: "complete",
          }
        );

        // Emit metrics for dashboards
        logger.metric("rodit_initialization_duration_ms", duration, {
          success: true,
          configType: type,
          configLevel: "partial",
          component: "RoditManager",
        });

        return minimalConfig;
      }

      logger.infoWithContext("RODiT config initialized successfully", {
        ...baseContext,
        roditId: own_rodit.token_id,
        duration: Date.now() - startTime,
      });

      // Port configuration removed as requested

      if (
        !own_rodit.metadata ||
        !own_rodit.metadata.subjectuniqueidentifier_url
      ) {
        logger.errorWithContext("Missing required metadata in RODiT", {
          ...baseContext,
          missingField: "subjectuniqueidentifier_url",
          step: "metadataCheck",
        });

        throw new Error(
          "Missing required metadata: subjectuniqueidentifier_url"
        );
      }

      const apiendpoint = own_rodit.metadata.subjectuniqueidentifier_url;

      logger.debugWithContext("Constructed API endpoint", {
        ...baseContext,
        api_ep: apiendpoint,
        step: "apiEndpointCreation",
      });

      logger.infoWithContext("Building full configuration object", {
        ...baseContext,
        step: "fullConfigCreation",
      });

      // Validate private key format before storing in config object
      let privateKeyToUse = credentials.signing_bytes_key;

      // Validate private key format (sensitive data not logged per security policy)

      // Detailed private key format validation and logging
      logger.debugWithContext("Private key format validation", {
        ...baseContext,
        keyType: typeof privateKeyToUse,
        isUint8Array: privateKeyToUse instanceof Uint8Array,
        isBuffer: Buffer.isBuffer(privateKeyToUse),
        length: privateKeyToUse?.length,
        step: "privateKeyValidation",
      });

      // Ensure private key is in the correct format (Uint8Array)
      if (privateKeyToUse && !(privateKeyToUse instanceof Uint8Array)) {
        if (Buffer.isBuffer(privateKeyToUse)) {
          logger.debugWithContext(
            "Converting Buffer to Uint8Array for private key",
            {
              ...baseContext,
              step: "privateKeyConversion",
              bufferLength: privateKeyToUse.length,
            }
          );

          // Store original buffer for comparison
          const originalBuffer = Buffer.from(privateKeyToUse);

          // Convert to Uint8Array
          privateKeyToUse = new Uint8Array(privateKeyToUse);

          // Verify conversion was successful
          logger.debugWithContext("Buffer to Uint8Array conversion result", {
            ...baseContext,
            step: "privateKeyConversionResult",
            originalType: "Buffer",
            convertedType: privateKeyToUse.constructor.name,
            isUint8Array: privateKeyToUse instanceof Uint8Array,
            originalLength: originalBuffer.length,
            convertedLength: privateKeyToUse.length,
          });
        } else if (
          typeof privateKeyToUse === "object" &&
          privateKeyToUse !== null
        ) {
          // Try to recover from a JSON-serialized Uint8Array or similar object
          logger.warnWithContext(
            "Attempting to recover private key from non-standard format",
            {
              ...baseContext,
              recoveryAttempt: true,
              objectKeys: Object.keys(privateKeyToUse).join(","),
              hasLength: privateKeyToUse.length !== undefined,
              lengthType: typeof privateKeyToUse.length,
            }
          );

          try {
            // If it's an array-like object, try to convert it to Uint8Array
            if (
              Array.isArray(privateKeyToUse) ||
              (privateKeyToUse.length !== undefined &&
                typeof privateKeyToUse.length === "number")
            ) {
              const originalData = privateKeyToUse;
              privateKeyToUse = new Uint8Array(
                Array.isArray(privateKeyToUse)
                  ? privateKeyToUse
                  : Array.from(privateKeyToUse)
              );

              logger.infoWithContext(
                "Successfully recovered private key from array-like object",
                {
                  ...baseContext,
                  recoveredKeyLength: privateKeyToUse.length,
                  recoveredIsUint8Array: privateKeyToUse instanceof Uint8Array,
                  originalType: originalData.constructor.name,
                }
              );
            } else {
              throw new Error("Cannot recover key - not an array-like object");
            }
          } catch (recoveryError) {
            logErrorWithMetrics({
              error: new Error(
                `Private key recovery failed: ${recoveryError.message}`
              ),
              context: {
                ...baseContext,
                keyType: typeof privateKeyToUse,
                step: "privateKeyRecoveryFailed",
                recoveryError: recoveryError.message,
              },
              metrics: [
                {
                  name: "private_key_recovery_failures",
                  value: 1,
                  tags: { configType: type },
                },
              ],
            });
            throw new Error("Private key must be a Uint8Array or Buffer");
          }
        } else {
          logErrorWithMetrics({
            error: new Error("Private key must be a Uint8Array or Buffer"),
            context: {
              ...baseContext,
              keyType: typeof privateKeyToUse,
              step: "privateKeyValidation",
            },
            metrics: [
              {
                name: "private_key_format_errors",
                value: 1,
                tags: { configType: type },
              },
            ],
          });
          throw new Error("Private key must be a Uint8Array or Buffer");
        }
      }

      // Private key validated and ready for storage (sensitive data not logged per security policy)

      const roditClient = {
        own_rodit,
        own_rodit_bytes_private_key: privateKeyToUse, // Use validated private key
        apiendpoint,
        port: "",
        iso639: config.get("API_DEFAULT_OPTIONS.ISO639"),
        iso3166: config.get("API_DEFAULT_OPTIONS.ISO3166"),
        iso15924: config.get("API_DEFAULT_OPTIONS.ISO15924"),
        timeoptions: config.get("API_DEFAULT_OPTIONS.TIMEOPTIONS"),
        tokenrenewaloptions: config.get("SECURITY_OPTIONS"),
      };

      logger.debugWithContext("Using RODiT token for configuration", {
        ...baseContext,
        roditId: own_rodit.token_id,
        accountId: account_id,
        step: "tokenUse",
      });

      logger.debugWithContext("Storing configuration in state manager", {
        ...baseContext,
        step: "storeConfig",
      });

      await stateManagerToUse.setConfigOwnRodit(roditClient);

      logger.infoWithContext("Configuration stored successfully", {
        ...baseContext,
        step: "configStored",
      });

      logger.debugWithContext("Converting implicit account ID to base64url", {
        ...baseContext,
        step: "keyConversion",
      });

      const session_base64url_jwk_public_key = Buffer.from(
        account_id,
        "hex"
      ).toString("base64url");

      logger.debugWithContext("Setting session base64url JWK public key", {
        ...baseContext,
        step: "setSessionKey",
      });

      // Set the client's own public key from the implicit account ID
      await stateManagerToUse.setOwnBase64urlJwkPublicKey(
        session_base64url_jwk_public_key
      );

      // Note: The server's public key should be set separately when it's received
      // during the handshake or authentication process

      const duration = Date.now() - startTime;
      logger.infoWithContext("RODiT configuration completed", {
        ...baseContext,
        duration,
        configLevel: "full",
        step: "complete",
      });

      // Emit metrics for dashboards
      logger.metric("rodit_initialization_duration_ms", duration, {
        success: true,
        configType: type,
        configLevel: "full",
        component: "RoditManager",
      });

      return roditClient;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics({
        error,
        context: {
          ...baseContext,
          duration,
        },
        metrics: [
          {
            name: "rodit_config_initialization_errors",
            value: 1,
            tags: { configType: type, errorType: error.name || "Unknown" },
          },
        ],
      });

      // Emit metrics for dashboards
      logger.metric("rodit_initialization_duration_ms", duration, {
        success: false,
        configType: type,
        component: "RoditManager",
        errorType: error.code || "UNKNOWN_ERROR",
      });
      logger.metric("rodit_initialization_errors_total", 1, {
        errorType: error.code || "UNKNOWN_ERROR",
        configType: type,
        component: "RoditManager",
        step: error.step || "unknown",
      });

      throw error;
    }
  }

  // Initialize RODiT SDK with the specified role
  async initializeRoditSdk(roles = {}) {
    // Handle both string and object inputs for backward compatibility
    const role = typeof roles === "string" ? roles : roles.role || "client";

    try {
      // Initialize vault and configuration using SDK
      await this.initializeCredentialsStore();

      // Initialize RODiT configuration for the specified role
      await this.initializeRoditConfig(role);

      logger.info(
        `Credentials (${RODIT_NEAR_CREDENTIALS_SOURCE}) initialized and RODiT configuration loaded for role: ${role}`
      );

      // Get and validate the configuration
      const roditClient = await stateManager.getConfigOwnRodit();
      if (!roditClient) {
        throw new Error(
          "Failed to initialize RODiT configuration: No configuration returned"
        );
      }

      // Apply rate limiting if configured
      const { own_rodit } = roditClient;
      if (
        own_rodit?.metadata?.max_requests &&
        own_rodit?.metadata?.maxrq_window
      ) {
        // This function should be provided by the application
        if (typeof stateManager.updateRateLimit === "function") {
          stateManager.updateRateLimit(
            own_rodit.metadata.max_requests,
            own_rodit.metadata.maxrq_window
          );
        }
      }

      return roditClient;
    } catch (error) {
      logger.error(`Failed to initialize RODiT SDK: ${error.message}`, {
        error,
      });
      throw new Error(`SDK initialization failed: ${error.message}`);
    }
  }
  /**
   * Get credentials for a specific type
   * @param {string} type - The credential type (e.g., 'sanctum', 'portal')
   * @returns {Promise<Object>} The credentials object
   */
  async getCredentials(type) {
    return await getCredentials(type);
  }
}

// Create and export a singleton instance
const roditManager = new RoditManager();

// Export the singleton instance directly to avoid any issues with destructuring
module.exports = roditManager;
