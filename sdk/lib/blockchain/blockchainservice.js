/**
 * Service for interacting with the blockchain network
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const config = require('../../services/configsdk');
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;

const baseModuleContext = createLogContext("BlockchainService", "module", {
  loadedAt: new Date().toISOString()
});

logger.debugWithContext("Loading blockchainservice.js module", baseModuleContext);

/**
 * Constants and Configuration
 */
const CONSTANTS = {
  NEAR_CONTRACT_ID: config.get("NEAR_CONTRACT_ID"),
  RODIT_ID_SZ: 128,
  RODIT_ID_PK_SZ: 32,
  RODIT_ID_SIGNATURE_SZ: 64,
  ED25519_KEY_SZ: 64,
};

const NEAR_RPC_URL = config.get("NEAR_RPC_URL");
// Simple in-memory TTL cache for RPC results
// Single TTL setting for all RPC caches (in milliseconds)
// Default value is defined centrally in configsdk.FALLBACK_DEFAULTS
const NEAR_CACHE_TTLS = parseInt(config.get("NEAR_CACHE_TTLS"));

const _rpcCache = new Map();
function _cacheGet(key) {
  const entry = _rpcCache.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt && entry.expiresAt <= Date.now()) {
    _rpcCache.delete(key);
    return undefined;
  }
  return entry.value;
}
function _cacheSet(key, value, ttlMs) {
  const expiresAt = ttlMs > 0 ? Date.now() + ttlMs : 0;
  _rpcCache.set(key, { value, expiresAt });
}
/**
 * Data models for RODiT Authentication
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

/**
 * RODiT token class that represents a Resource Ownership and Digital Identity Token
 */
class RODiT {
  constructor() {
    this.token_id = "";
    this.owner_id = "";
    this.metadata = {
      openapijson_url: "",
      not_after: "",
      not_before: "",
      max_requests: "",
      maxrq_window: "",
      webhook_url: "",
      webhook_cidr: "",
      userselected_dn: "",
      allowed_cidr: "",
      allowed_iso3166list: "",
      jwt_duration: "",
      permissioned_routes: "",
      subjectuniqueidentifier_url: "",
      serviceprovider_id: "",
      serviceprovider_signature: "",
    };
  }
}

/**
 * Payload class for NEP-413 standard
 */
class PayloadNEP413 {
  constructor(props) {
    this.tag = props.tag || 2147484061;
    this.message = props.message;
    if (props.nonce instanceof Uint8Array) {
      if (props.nonce.length !== 32) {
        throw new Error("Nonce must be exactly 32 bytes");
      }
      this.nonce = props.nonce;
    } else if (
      Array.isArray(props.nonce) ||
      (typeof props.nonce === "object" && props.nonce !== null)
    ) {
      const nonceArray = Array.isArray(props.nonce)
        ? props.nonce
        : Object.values(props.nonce);
      if (nonceArray.length !== 32) {
        throw new Error("Nonce must be exactly 32 bytes");
      }
      this.nonce = new Uint8Array(nonceArray);
    } else {
      throw new Error(
        "Invalid nonce format - must be Uint8Array or convertible to Uint8Array"
      );
    }
    this.recipient = props.recipient;
    this.callbackUrl = props.callbackUrl;
  }
}

/**
 * Schema for NEP-413 payload in Borsh format
 */
const PayloadNEP413Schema = {
  struct: {
    tag: "u32",
    message: "string",
    nonce: { array: { type: "u8", len: 32 } },
    recipient: "string",
    callbackUrl: { option: "string" },
  },
};

/**
 * Service for interacting with the blockchain network
 */

  async function nearorg_rpc_timestamp() {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext(
      "BlockchainService",
      "nearorg_rpc_timestamp",
      {
        requestId,
        rpcUrl: NEAR_RPC_URL
      }
    );
    
    logger.debugWithContext("Fetching blockchain timestamp", baseContext);

    try {
      // Cache check
      const cacheKey = `ts:${NEAR_RPC_URL}`;
      const cached = _cacheGet(cacheKey);
      if (cached !== undefined) {
        logger.debugWithContext("Cache hit for blockchain timestamp", baseContext);
        return cached;
      }

      const jsonData = {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: {
          finality: "final",
        },
      };

      const fetchStartTime = Date.now();
      const response = await fetch(NEAR_RPC_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(jsonData),
      });
      const fetchDuration = Date.now() - fetchStartTime;

      logger.debugWithContext("RPC response received", {
        ...baseContext,
        statusCode: response.status,
        fetchDuration
      });

      if (!response.ok) {
        const duration = Date.now() - startTime;
        
        // Add metric for failed RPC calls
        logger.metric("near_rpc_calls", fetchDuration, {
          result: "http_error",
          status_code: response.status,
          method: "block",
        });
        
        logErrorWithMetrics(
          "HTTP error from blockchain RPC",
          {
            ...baseContext,
            statusCode: response.status,
            statusText: response.statusText,
            duration
          },
          new Error(`HTTP error! status: ${response.status}`),
          "near_rpc_http_error",
          {
            result: "error",
            status_code: response.status,
            method: "block",
            duration
          }
        );

        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const parseStartTime = Date.now();
      const parsedJson = await response.json();
      const parseDuration = Date.now() - parseStartTime;

      logger.debugWithContext("RPC response parsed", {
        ...baseContext,
        parseDuration
      });

      if (parsedJson.error) {
        const duration = Date.now() - startTime;
        
        // Add metric for RPC errors
        logger.metric("near_rpc_errors", 1, {
          error_code: parsedJson.error.code || "unknown",
          method: "block",
        });
        
        logErrorWithMetrics(
          "RPC error response",
          {
            ...baseContext,
            rpcError: parsedJson.error.message,
            rpcErrorCode: parsedJson.error.code,
            duration
          },
          new Error(`Error 017: ${parsedJson.error.message}`),
          "near_rpc_error_response",
          {
            result: "error",
            error_code: parsedJson.error.code || "unknown",
            method: "block",
            duration
          }
        );

        throw new Error(`Error 017: ${parsedJson.error.message}`);
      }

      const timestamp = parsedJson.result?.header?.timestamp;
      const totalDuration = Date.now() - startTime;

      logger.infoWithContext("Blockchain timestamp fetched successfully", {
        ...baseContext,
        duration: totalDuration,
        fetchDuration,
        parseDuration,
        timestamp: timestamp || "0"
      });

      // Add metric for successful RPC calls
      logger.metric("near_rpc_calls", totalDuration, {
        result: "success",
        method: "block",
      });
      // Store in cache using unified TTL setting
      const tsValue = timestamp ? timestamp.toString() : "0";
      _cacheSet(cacheKey, tsValue, NEAR_CACHE_TTLS);
      return tsValue;
    } catch (error) {
      const duration = Date.now() - startTime;

      // Add metrics for timestamp errors
      logger.metric("near_rpc_timestamp_errors", 1, {
        error_type: error.name || "Unknown",
      });
      
      logErrorWithMetrics(
        "Error fetching blockchain timestamp",
        {
          ...baseContext,
          duration,
          rpcUrl: NEAR_RPC_URL
        },
        error,
        "near_rpc_timestamp",
        {
          result: "error",
          error_type: error.name || "Unknown",
          duration
        }
      );

      throw error;
    }
  }

  /**
   * Fetches a RODiT token by ID from the NEAR blockchain
   * 
   * @param {string} roditid - RODiT token ID to fetch
   * @returns {Promise<RODiT>} RODiT token object
   */
  async function nearorg_rpc_tokenfromroditid(roditid) {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext(
      "BlockchainService",
      "nearorg_rpc_tokenfromroditid",
      {
        requestId,
        roditId: roditid,
        nearContractId: CONSTANTS.NEAR_CONTRACT_ID,
        nearRpcUrl: NEAR_RPC_URL
      }
    );

    // Security check: Handle null, undefined, or invalid roditid
    // This is important for security tests that intentionally send invalid tokens
    if (!roditid) {
      logger.warnWithContext("Attempted to fetch RODiT with null/undefined ID", {
        ...baseContext,
        result: 'failure',
        reason: 'Null or undefined RODiT'
      });
      // Return an empty RODiT object instead of throwing an error
      // This allows the authentication flow to continue and properly reject the invalid token
      return new RODiT();
    }

    logger.infoWithContext("Fetching RODiT token by ID", {
      ...baseContext,
      result: 'call',
      reason: 'Fetch RODiT token by ID requested'
    }); // Function call log

    // Cache check
    const cacheKey = `rodit_by_id:${CONSTANTS.NEAR_CONTRACT_ID}:${roditid}`;
    const cachedRodit = _cacheGet(cacheKey);
    if (cachedRodit) {
      logger.debugWithContext("Cache hit for RODiT token by ID", {
        ...baseContext,
        cached: true
      });
      return cachedRodit;
    }

    try {
      const args = { token_id: roditid };
      const argsBase64 = Buffer.from(JSON.stringify(args)).toString("base64");

      const json_data = {
        jsonrpc: "2.0",
        id: CONSTANTS.NEAR_CONTRACT_ID,
        method: "query",
        params: {
          request_type: "call_function",
          finality: "final",
          account_id: CONSTANTS.NEAR_CONTRACT_ID,
          method_name: "rodit_token",
          args_base64: argsBase64,
        },
      };

      const fetchStartTime = Date.now();
      const response = await fetch(NEAR_RPC_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(json_data),
      });
      const fetchDuration = Date.now() - fetchStartTime;

      logger.debugWithContext("RPC response received", {
        ...baseContext,
        statusCode: response.status,
        fetchDuration
      });

      if (!response.ok) {
        const duration = Date.now() - startTime;
        
        // Add metric for failed RPC calls
        logger.metric("near_rpc_calls", fetchDuration, {
          result: "failure",
          reason: `HTTP error from blockchain RPC: status ${response.status}`,
          status_code: response.status,
          method: "rodit_token",
        });
        
        logErrorWithMetrics(
          "HTTP error from blockchain RPC",
          {
            ...baseContext,
            statusCode: response.status,
            duration,
            result: 'failure',
            reason: `HTTP error from blockchain RPC: status ${response.status}`
          },
          new Error(`HTTP error! status: ${response.status}`),
          "near_rpc_http_error",
          {
            result: "failure",
            reason: `HTTP error from blockchain RPC: status ${response.status}`,
            status_code: response.status,
            method: "rodit_token",
            duration
          }
        );

        return new RODiT();
      }

      const parseStartTime = Date.now();
      const responseText = await response.text();
      const parsedJson = JSON.parse(responseText);
      const parseDuration = Date.now() - parseStartTime;

      logger.debugWithContext("RPC response parsed", {
        ...baseContext,
        parseDuration,
        hasResult: !!parsedJson.result
      });

      if (parsedJson.result && parsedJson.result.error) {
        const duration = Date.now() - startTime;
        
        // Add metric for WASM errors
        logger.metric("near_rpc_wasm_errors", 1, {
          method: "rodit_token",
          rodit_id: roditid,
          result: 'failure',
          reason: `WASM execution error: ${parsedJson.result.error}`
        });
        
        logErrorWithMetrics(
          "WASM execution error",
          {
            ...baseContext,
            wasmError: parsedJson.result.error,
            duration,
            result: 'failure',
            reason: `WASM execution error: ${parsedJson.result.error}`
          },
          new Error(`WASM execution error: ${parsedJson.result.error}`),
          "near_rpc_wasm_error",
          {
            method: "rodit_token",
            rodit_id: roditid,
            duration,
            result: 'failure',
            reason: `WASM execution error: ${parsedJson.result.error}`
          }
        );

        return new RODiT();
      }

      const resultArray = parsedJson.result.result;
      if (!Array.isArray(resultArray)) {
        const duration = Date.now() - startTime;
        
        // Add metric for format errors
        logger.metric("near_rpc_format_errors", 1, {
          method: "rodit_token",
          rodit_id: roditid,
          error_type: "invalid_array",
          result: 'failure',
          reason: 'Invalid result format: not an array'
        });
        
        logErrorWithMetrics(
          "Invalid result format",
          {
            ...baseContext,
            resultType: typeof resultArray,
            duration,
            result: 'failure',
            reason: 'Invalid result format: not an array'
          },
          new Error("Result is not an array"),
          "near_rpc_format_error",
          {
            method: "rodit_token",
            rodit_id: roditid,
            error_type: "invalid_array",
            duration,
            result: 'failure',
            reason: 'Invalid result format: not an array'
          }
        );

        return new RODiT();
      }

      const decodeStartTime = Date.now();
      const resultString = new TextDecoder().decode(new Uint8Array(resultArray));
      let parsed;
      
      try {
        parsed = JSON.parse(resultString);
      } catch (error) {
        logErrorWithMetrics(
          "Failed to parse RODiT data",
          {
            ...baseContext,
            error: error.message,
            result: 'failure',
            reason: `Failed to parse RODiT data: ${error.message}`
          },
          error,
          "rodit_parse_error",
          {
            error_type: error.name || "Unknown",
            rodit_id: roditid,
            result: 'failure',
            reason: `Failed to parse RODiT data: ${error.message}`
          }
        );
        return new RODiT();
      }
      
      const decodeDuration = Date.now() - decodeStartTime;

      logger.debugWithContext("RODiT data decoded", {
        ...baseContext,
        decodeDuration,
        isNull: parsed === null,
        hasTokenId: parsed && !!parsed.token_id,
        parsedType: typeof parsed
      }); // Context-only debug log, does not expose secrets

      const rodit = new RODiT();
      
      // Handle Option<JsonToken> return type - null means token not found
      if (parsed === null) {
        logger.warnWithContext("RODiT token not found on blockchain", {
          ...baseContext,
          targetTokenId: roditid,
          result: 'not_found',
          reason: 'RODiT token does not exist on blockchain'
        });
        // Return empty RODiT object - this will cause authentication to fail properly
        return rodit;
      }
      
      if (parsed && typeof parsed === 'object') {
        // Debug logging for owner_id issue investigation
        logger.debugWithContext("RAW RODiT data from blockchain", {
          ...baseContext,
          parsedData: parsed,
          parsedOwnerIdField: parsed.owner_id,
          parsedOwnerIdType: typeof parsed.owner_id,
          parsedKeys: Object.keys(parsed),
          hasMetadata: !!parsed.metadata,
          metadataServiceProviderId: parsed.metadata?.serviceprovider_id
        });
        
        Object.assign(rodit, parsed);
        
        // Debug logging after assignment
        logger.debugWithContext("RODiT object after assignment", {
          ...baseContext,
          roditOwnerId: rodit.owner_id,
          roditOwnerIdType: typeof rodit.owner_id,
          roditTokenId: rodit.token_id,
          roditMetadata: rodit.metadata
        });
      } else {
        logger.warnWithContext("Invalid RODiT data format", {
          ...baseContext,
          parsedType: typeof parsed,
          parsedValue: parsed,
          result: 'failure',
          reason: 'Invalid RODiT data format from blockchain'
        });
      }

      const totalDuration = Date.now() - startTime;
      const hasValidData = !!rodit.token_id && !!rodit.owner_id;

      logger.infoWithContext("RODiT token fetched", {
        ...baseContext,
        duration: totalDuration,
        retrieved: hasValidData,
        fetchDuration,
        parseDuration,
        decodeDuration,
        result: 'success',
        reason: hasValidData ? 'RODiT token successfully fetched' : 'RODiT token fetch returned empty or incomplete data'
      });

      // Add metrics for successful RPC calls
      logger.metric("near_rpc_calls", totalDuration, {
        result: "success",
        reason: hasValidData ? 'RODiT token successfully fetched' : 'RODiT token fetch returned empty or incomplete data',
        method: "rodit_token",
        data_found: hasValidData ? "true" : "false"
      });
      // Cache successful lookups only
      if (hasValidData) {
        _cacheSet(cacheKey, rodit, NEAR_CACHE_TTLS);
      }
      return rodit;
    } catch (error) {
      const duration = Date.now() - startTime;

      // Add metrics for token fetch errors
      logger.metric("near_rpc_token_errors", 1, {
        error_type: error.name || "Unknown",
        rodit_id: roditid,
        result: 'failure',
        reason: `Failed to fetch RODiT token: ${error.message}`
      });
      
      logErrorWithMetrics(
        "Failed to fetch RODiT token",
        {
          ...baseContext,
          duration,
          result: 'failure',
          reason: `Failed to fetch RODiT token: ${error.message}`
        },
        error,
        "near_rpc_token_fetch",
        {
          result: 'failure',
          reason: `Failed to fetch RODiT token: ${error.message}`,
          error_type: error.name || "Unknown",
          rodit_id: roditid,
          duration
        }
      );

      return new RODiT();
    }
  }

  /**
   * Checks account state on the blockchain
   * 
   * @param {string} accountId - Account ID to check
   * @returns {Promise<boolean>} Whether the account exists
   */
  async function nearorg_rpc_state(accountId) {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext(
      "BlockchainService",
      "nearorg_rpc_state",
      {
        requestId,
        accountId,
        contractId: CONSTANTS.NEAR_CONTRACT_ID
      }
    );

    logger.infoWithContext("Checking account state on blockchain", {
      ...baseContext,
      result: 'call',
      reason: 'Account state check requested'
    }); // Function call log

    // Cache check
    const cacheKey = `state:${accountId}`;
    const cachedState = _cacheGet(cacheKey);
    if (cachedState !== undefined) {
      logger.debugWithContext("Cache hit for account state", {
        ...baseContext,
        cachedState
      });
      return cachedState;
    }

    try {
      const jsonData = {
        jsonrpc: "2.0",
        id: CONSTANTS.NEAR_CONTRACT_ID,
        method: "query",
        params: {
          request_type: "view_account",
          finality: "final",
          account_id: accountId
        }
      };

      const response = await fetch(NEAR_RPC_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(jsonData),
      });

      const responseText = await response.json();

      if (JSON.stringify(responseText).includes("does not exist while viewing")) {
        const duration = Date.now() - startTime;

        logger.warnWithContext("Account does not exist in blockchain", {
          ...baseContext,
          duration,
          needsFunding: true,
          result: 'failure',
          reason: 'Account does not exist in blockchain'
        });

        // Emit metrics for dashboards
        logger.metric("account_state_check_duration_ms", duration, {
          component: "BlockchainService",
          success: false,
          accountExists: false,
          result: 'failure',
          reason: 'Account does not exist in blockchain'
        });
        logger.metric("non_existent_accounts_total", 1, {
          component: "BlockchainService",
          accountId,
          result: 'failure',
          reason: 'Account does not exist in blockchain'
        });
        _cacheSet(cacheKey, false, NEAR_CACHE_TTLS);
        return false;
      }

      // If account exists
      const duration = Date.now() - startTime;
      logger.infoWithContext("Account exists in blockchain", {
        ...baseContext,
        duration,
        result: 'success',
        reason: 'Account exists in blockchain'
      });
      logger.metric("account_state_check_duration_ms", duration, {
        component: "BlockchainService",
        success: true,
        accountExists: true,
        result: 'success',
        reason: 'Account exists in blockchain'
      });
      _cacheSet(cacheKey, true, NEAR_CACHE_TTLS);
      return true;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.metric("account_state_check_duration_ms", duration, {
        component: "BlockchainService",
        success: false,
        accountExists: false,
        result: 'failure',
        reason: error.message || 'Unknown error during account state check'
      });
      logErrorWithMetrics(
        "Error checking account state on blockchain",
        {
          ...baseContext,
          duration,
          result: 'failure',
          reason: error.message || 'Unknown error during account state check'
        },
        error,
        "account_state_check",
        {
          result: 'failure',
          reason: error.message || 'Unknown error during account state check',
          error_type: error.constructor?.name || 'Error',
          duration
        }
      );
      return false;
    }
  }

  /**
   * Fetches RODiT tokens for an account
   * 
   * @param {string} account_id - Account ID to fetch tokens for
   * @returns {Promise<RODiT>} First RODiT token for the account
   */
  async function nearorg_rpc_tokensfromaccountid(account_id) {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext(
      "BlockchainService",
      "nearorg_rpc_tokensfromaccountid",
      {
        requestId,
        accountId: account_id,
        contractId: CONSTANTS.NEAR_CONTRACT_ID
      }
    );

    logger.infoWithContext("Fetching RODiT tokens for account", {
      ...baseContext,
      result: 'call',
      reason: 'Fetch RODiT tokens for account requested'
    }); // Function call log

    // Cache check
    const cacheKey = `tokens_by_account:${CONSTANTS.NEAR_CONTRACT_ID}:${account_id}`;
    const cachedTokens = _cacheGet(cacheKey);
    if (cachedTokens) {
      logger.debugWithContext("Cache hit for RODiT tokens by account", {
        ...baseContext,
        cached: true,
        firstTokenId: cachedTokens.token_id
      });
      return cachedTokens;
    }

    try {
      const args = JSON.stringify({
        account_id: account_id,
        from_index: "0",  // String format for U128
        limit: 1          // Only retrieve the first token
      });

      const jsonData = {
        jsonrpc: "2.0",
        id: CONSTANTS.NEAR_CONTRACT_ID,
        method: "query",
        params: {
          request_type: "call_function",
          finality: "final",
          account_id: CONSTANTS.NEAR_CONTRACT_ID,
          method_name: "rodit_tokens_for_owner",
          args_base64: Buffer.from(args).toString("base64"),
        },
      };

      logger.debugWithContext("Sending RPC request for account tokens", {
        ...baseContext,
        rpcMethod: "rodit_tokens_for_owner"
      });

      const response = await fetch(NEAR_RPC_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(jsonData),
      });

      const responseText = await response.text();
      const parsedJson = JSON.parse(responseText);

      if (parsedJson.result && parsedJson.result.error) {
        const duration = Date.now() - startTime;

        // Emit metrics for dashboards
        logger.metric("account_tokens_fetch_duration_ms", duration, {
          component: "BlockchainService",
          success: false,
          result: 'failure',
          reason: `WASM execution error: ${parsedJson.result.error}`
        });
        logger.metric("blockchain_rpc_errors_total", 1, {
          component: "BlockchainService",
          method: "tokens_from_account",
          result: 'failure',
          reason: `WASM execution error: ${parsedJson.result.error}`
        });
        
        logErrorWithMetrics(
          "WASM execution error",
          {
            ...baseContext,
            duration,
            wasmError: parsedJson.result.error,
            result: 'failure',
            reason: `WASM execution error: ${parsedJson.result.error}`
          },
          new Error(`Smart contract execution failed: ${parsedJson.result.error}`),
          "account_tokens_fetch",
          {
            result: 'failure',
            reason: `WASM execution error: ${parsedJson.result.error}`,
            error_type: "WASM_ERROR",
            duration
          }
        );

        throw new Error(
          `Smart contract execution failed: ${parsedJson.result.error}`
        );
      }

      const resultArray = parsedJson.result.result;
      if (!Array.isArray(resultArray)) {
        const duration = Date.now() - startTime;

        // Emit metrics for dashboards
        logger.metric("account_tokens_fetch_duration_ms", duration, {
          component: "BlockchainService",
          success: false,
          error: "INVALID_RESULT_FORMAT",
        });
        logger.metric("blockchain_rpc_errors_total", 1, {
          component: "BlockchainService",
          method: "tokens_from_account",
          error: "INVALID_RESULT_FORMAT",
        });
        
        logErrorWithMetrics(
          "Invalid result format from blockchain",
          {
            ...baseContext,
            duration,
            resultType: typeof resultArray
          },
          new Error("Result is not an array"),
          "account_tokens_fetch",
          {
            result: "error",
            error_type: "INVALID_RESULT_FORMAT",
            duration
          }
        );

        throw new Error("Result is not an array");
      }

      const resultString = new TextDecoder().decode(new Uint8Array(resultArray));
      const resultStruct = JSON.parse(resultString);

      if (!Array.isArray(resultStruct) || resultStruct.length === 0) {
        const duration = Date.now() - startTime;

        logger.warnWithContext("No RODiT instances found for account", {
          ...baseContext,
          duration,
          tokenCount: 0
        });

        // Emit metrics for dashboards
        logger.metric("account_tokens_fetch_duration_ms", duration, {
          component: "BlockchainService",
          success: true,
          tokenCount: 0,
        });
        logger.metric("empty_account_tokens_total", 1, {
          component: "BlockchainService",
          accountId: account_id,
        });

        const emptyRodit = new RODiT();
        return emptyRodit;
      }

      const rodit = new RODiT();
      Object.assign(rodit, resultStruct[0]);

      const duration = Date.now() - startTime;
      logger.debugWithContext("Successfully retrieved RODiT tokens", {
        ...baseContext,
        duration,
        tokenCount: resultStruct.length,
        firstTokenId: rodit.token_id
      });

      // Emit metrics for dashboards
      logger.metric("account_tokens_fetch_duration_ms", duration, {
        component: "BlockchainService",
        success: true,
        tokenCount: resultStruct.length,
      });
      // Cache successful lookups
      _cacheSet(cacheKey, rodit, NEAR_CACHE_TTLS);
      return rodit;
    } catch (error) {
      const duration = Date.now() - startTime;

      // Emit metrics for dashboards
      logger.metric("account_tokens_fetch_duration_ms", duration, {
        component: "BlockchainService",
        success: false,
        result: 'failure',
        reason: `Failed to fetch RODiT tokens: ${error.message}`
      });
      logger.metric("blockchain_rpc_errors_total", 1, {
        component: "BlockchainService",
        method: "tokens_from_account",
        result: 'failure',
        reason: `Failed to fetch RODiT tokens: ${error.message}`
      });
      
      logErrorWithMetrics(
        "Failed to fetch RODiT tokens",
        {
          ...baseContext,
          duration,
          result: 'failure',
          reason: `Failed to fetch RODiT tokens: ${error.message}`
        },
        error,
        "account_tokens_fetch",
        {
          result: 'failure',
          reason: `Failed to fetch RODiT tokens: ${error.message}`,
          error_type: error.constructor.name,
          duration
        }
      );

      throw error;
    }
  }

  /**
   * Fetches a public key in bytes format for an account
   * 
   * @param {string} accountId - Account ID
   * @returns {Promise<Uint8Array>} Public key bytes
   */
  async function nearorg_rpc_fetchpublickeybytes(accountId) {
    const requestId = ulid();
    const startTime = Date.now();
    
    const baseContext = createLogContext(
      "BlockchainService",
      "nearorg_rpc_fetchpublickeybytes",
      {
        requestId,
        accountId
      }
    );

    logger.debugWithContext("Fetching public key bytes", baseContext);

    try {
      // Cache check
      const cacheKey = `pubkey_bytes:${accountId}`;
      const cached = _cacheGet(cacheKey);
      if (cached) {
        logger.debugWithContext("Cache hit for public key bytes", {
          ...baseContext,
          keyLength: cached.length
        });
        return cached;
      }
      const isImplicitAccount = /^[0-9a-f]{64}$/.test(accountId);

      if (isImplicitAccount) {
        logger.debugWithContext("Account is implicit, using direct hex encoding", baseContext);

        const result = new Uint8Array(Buffer.from(accountId, "hex"));

        const duration = Date.now() - startTime;
        logger.debugWithContext(
          "Successfully retrieved public key bytes from implicit account",
          {
            ...baseContext,
            duration,
            keyLength: result.length
          }
        );

        // Emit metrics for dashboards
        logger.metric("public_key_fetch_duration_ms", duration, {
          method: "direct_hex",
          component: "BlockchainService",
          success: true,
        });
        // Cache result
        _cacheSet(cacheKey, result, NEAR_CACHE_TTLS);
        return result;
      }

      logger.debugWithContext("Account is named, fetching RODiT token", baseContext);

      const rodit = await nearorg_rpc_tokensfromaccountid(accountId);

      if (!rodit || !rodit.owner_id) {
        const duration = Date.now() - startTime;
        
        // Emit metrics for dashboards
        logger.metric("public_key_fetch_duration_ms", duration, {
          method: "rodit_lookup",
          component: "BlockchainService",
          success: false,
          error: "NO_VALID_RODIT",
        });
        logger.metric("public_key_fetch_errors_total", 1, {
          method: "rodit_lookup",
          component: "BlockchainService",
          error: "NO_VALID_RODIT",
        });
        
        logErrorWithMetrics(
          "No valid RODiT found for account",
          {
            ...baseContext,
            duration,
            error: "NO_VALID_RODIT"
          },
          new Error(`No valid RODiT found for account: ${accountId}`),
          "public_key_fetch",
          {
            result: "error",
            error_type: "NO_VALID_RODIT",
            method: "rodit_lookup",
            duration
          }
        );

        throw new Error(`No valid RODiT found for account: ${accountId}`);
      }

      const result = new Uint8Array(Buffer.from(rodit.owner_id, "hex"));

      const duration = Date.now() - startTime;
      logger.debugWithContext("Successfully retrieved public key bytes from RODiT", {
        ...baseContext,
        duration,
        keyLength: result.length
      });

      // Emit metrics for dashboards
      logger.metric("public_key_fetch_duration_ms", duration, {
        method: "rodit_lookup",
        component: "BlockchainService",
        success: true,
      });
      // Cache result using unified TTL setting
      _cacheSet(cacheKey, result, NEAR_CACHE_TTLS);
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;

      // Emit metrics for dashboards
      logger.metric("public_key_fetch_duration_ms", duration, {
        component: "BlockchainService",
        success: false,
        error: error.constructor.name,
      });
      logger.metric("public_key_fetch_errors_total", 1, {
        component: "BlockchainService",
        error: error.constructor.name,
      });
      
      logErrorWithMetrics(
        "Failed to fetch public key bytes",
        {
          ...baseContext,
          duration
        },
        error,
        "public_key_fetch",
        {
          result: "error",
          error_type: error.constructor.name,
          duration
        }
      );

      throw new Error(`Error retrieving public key: ${error.message}`);
    }
  }

  async function nearorg_rpc_listpublicagents(limitsandcursor = {}) {
    const { limit = 20, cursor } = limitsandcursor;
    // Convert cursor to from_index for rodit_tokens method
    const from_index = cursor ? cursor : null;
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext(
      "BlockchainService",
      "nearorg_rpc_listpublicagents",
      {
        requestId,
        limit,
        cursor
      }
    );
    logger.debugWithContext("Fetching public agents list (using rodit_tokens)", baseContext);
  try {
    logger.debugWithContext("DEBUG: Entered try block", baseContext);
    const args = { from_index, limit };
    const argsBase64 = Buffer.from(JSON.stringify(args)).toString("base64");
    const json_data = {
      jsonrpc: "2.0",
      id: CONSTANTS.NEAR_CONTRACT_ID,
      method: "query",
      params: {
        request_type: "call_function",
        finality: "final",
        account_id: CONSTANTS.NEAR_CONTRACT_ID,
        method_name: "rodit_tokens",
        args_base64: argsBase64
      }
    };

    const rpcStart = Date.now();
    logger.debugWithContext("DEBUG: About to make fetch call", baseContext);
    const response = await fetch(NEAR_RPC_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(json_data)
    });
    const rpcDuration = Date.now() - rpcStart;

    logger.debugWithContext("DEBUG: Fetch completed", { ...baseContext, status: response.status });
    if (!response.ok) {
      logger.metric("near_rpc_calls", rpcDuration, { result: "failure", method: "list_public_agents", status_code: response.status });
      throw new Error(`HTTP error ${response.status}`);
    }

    logger.debugWithContext("DEBUG: About to parse JSON", baseContext);
    const parsed = await response.json();
    logger.debugWithContext("DEBUG: JSON parsed", baseContext);
    logger.debugWithContext("DEBUG: Inspecting parsed response", {
      ...baseContext,
      parsedKeys: Object.keys(parsed),
      hasResult: !!parsed.result,
      resultKeys: parsed.result ? Object.keys(parsed.result) : null,
      resultBase64Length: parsed.result?.result?.length || 0
    });
    const resultBase64 = parsed.result?.result;
    if (!resultBase64) {
      logger.debugWithContext("DEBUG: No resultBase64 found, returning empty list", {
        ...baseContext,
        fullParsedResponse: parsed
      });
      return { list_agents: [], nextCursor: null };
    }

    logger.debugWithContext("DEBUG: About to decode base64", baseContext);
    const buf = Buffer.from(resultBase64, "base64");
    const decoded = new TextDecoder().decode(buf);
    logger.debugWithContext("DEBUG: About to parse payload JSON", baseContext);
    const payload = JSON.parse(decoded);
    logger.debugWithContext("DEBUG: Payload parsed successfully", baseContext);

    const totalDuration = Date.now() - startTime;
    logger.metric("near_rpc_calls", totalDuration, { result: "success", method: "list_public_agents" });
  
    // Log the complete response data (rodit_tokens)
    logger.debugWithContext("Public agents list retrieved (rodit_tokens)", {
      ...baseContext,
      duration: totalDuration,
      tokenCount: payload?.length || 0,
      tokens: payload
    });
    
    // Transform rodit_tokens response to match expected list_agents format
    const transformedResponse = {
      list_agents: payload || [],
      nextCursor: payload && payload.length === limit ? (from_index || 0) + limit : null
    };
  
    // Cache successful response
    _cacheSet(cacheKey, transformedResponse, 30000); // 30 seconds for public agents list
    return transformedResponse;
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.metric("near_rpc_errors", 1, { method: "list_public_agents" });
    logErrorWithMetrics(
      "Error listing public agents",
      { ...baseContext, duration },
      error,
      "near_rpc_listpublicagents",
      { result: "error", duration }
    );
    throw error;
  }
}

/**
 * Fetches list of access keys for an account
 * @param {string} accountId
 */
async function nearorg_rpc_accesskeys(accountId) {
  const requestId = ulid();
  const startTime = Date.now();
  const baseContext = createLogContext("BlockchainService","nearorg_rpc_accesskeys",{requestId,accountId});
  logger.debugWithContext("Fetching access keys", baseContext);
  // Cache check
  const cacheKey = `accesskeys:${accountId}`;
  const cached = _cacheGet(cacheKey);
  if (cached !== undefined) {
    logger.debugWithContext("Cache hit for access keys", { ...baseContext });
    return cached;
  }
  const json_data = {
    jsonrpc:"2.0", id:CONSTANTS.NEAR_CONTRACT_ID, method:"query", params:{request_type:"view_access_key_list", finality:"final", account_id:accountId}
  };
  const response = await fetch(NEAR_RPC_URL,{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(json_data)});
  const duration = Date.now() - startTime;
  if(!response.ok){ logger.metric("near_rpc_calls", duration,{result:"failure",method:"view_access_key_list",status_code:response.status}); throw new Error(`HTTP ${response.status}`);} 
  const parsed = await response.json();
  logger.metric("near_rpc_calls", duration,{result:"success",method:"view_access_key_list"});
  // Cache successful result
  _cacheSet(cacheKey, parsed.result, NEAR_CACHE_TTLS);
  return parsed.result;
}

/**
 * Fetches owner (account ID) of a RODiT token
 * @param {string} token_id
 */
async function nearorg_rpc_rodit_owner(token_id){
  const requestId = ulid();
  const startTime = Date.now();
  const baseContext = createLogContext("BlockchainService","nearorg_rpc_rodit_owner",{requestId,token_id});
  logger.debugWithContext("Fetching RODiT owner", baseContext);
  // Cache check
  const cacheKey = `rodit_owner:${token_id}`;
  const cached = _cacheGet(cacheKey);
  if (cached !== undefined) {
    logger.debugWithContext("Cache hit for RODiT owner", { ...baseContext });
    return cached;
  }
  const args = { token_id };
  const argsBase64 = Buffer.from(JSON.stringify(args)).toString("base64");
  const json_data = {jsonrpc:"2.0", id:CONSTANTS.NEAR_CONTRACT_ID, method:"query", params:{request_type:"call_function", finality:"final", account_id:CONSTANTS.NEAR_CONTRACT_ID, method_name:"rodit_token_owner", args_base64:argsBase64 }};
  const response = await fetch(NEAR_RPC_URL,{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(json_data)});
  const duration = Date.now()-startTime;
  if(!response.ok){ logger.metric("near_rpc_calls",duration,{result:"failure",method:"rodit_token_owner",status_code:response.status}); throw new Error(`HTTP ${response.status}`);} 
  const parsed = await response.json();
  logger.metric("near_rpc_calls",duration,{result:"success",method:"rodit_token_owner"});
  if(parsed.result && parsed.result.result){ const buf = Buffer.from(parsed.result.result,"base64"); const value = JSON.parse(new TextDecoder().decode(buf)); _cacheSet(cacheKey, value, NEAR_CACHE_TTLS); return value; }
  return null;
}

/**
 * Retrieves a nonce for a RODiT token from the agent-auth contract
 * @param {string} token_id
 * @returns {Promise<string>} nonce
 */
async function nearorg_rpc_getnonce(token_id) {
  const requestId = ulid();
  const startTime = Date.now();
  const baseContext = createLogContext("BlockchainService","nearorg_rpc_getnonce",{requestId,token_id});
  const args = { token_id };
  const argsBase64 = Buffer.from(JSON.stringify(args)).toString("base64");
  const json_data = {jsonrpc:"2.0", id:CONSTANTS.NEAR_CONTRACT_ID, method:"query", params:{request_type:"call_function", finality:"final", account_id:CONSTANTS.NEAR_CONTRACT_ID, method_name:"get_nonce", args_base64:argsBase64 }};
  const response = await fetch(NEAR_RPC_URL,{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(json_data)});
  const duration = Date.now()-startTime;
  if(!response.ok){ logger.metric("near_rpc_calls", duration,{result:"failure",method:"get_nonce",status_code:response.status}); throw new Error(`HTTP ${response.status}`);} 
  const parsed = await response.json();
  logger.metric("near_rpc_calls", duration,{result:"success",method:"get_nonce"});
  if(parsed.result && parsed.result.result){ return Buffer.from(parsed.result.result,"base64").toString(); }
  return null;
}

/**
 * Verifies a signature for RODiT Authentication
 * @param {string} token_id
 * @param {string} nonce
 * @param {string} sig - base58 or hex signature
 * @returns {Promise<boolean>} verification result
 */
async function nearorg_rpc_verifysignature(token_id, nonce, sig) {
  const requestId = ulid();
  const startTime = Date.now();
  const baseContext = createLogContext("BlockchainService","nearorg_rpc_verifysignature",{requestId,token_id});
  const args = { token_id, nonce, sig };
  const argsBase64 = Buffer.from(JSON.stringify(args)).toString("base64");
  const json_data = {jsonrpc:"2.0", id:CONSTANTS.NEAR_CONTRACT_ID, method:"query", params:{request_type:"call_function", finality:"final", account_id:CONSTANTS.NEAR_CONTRACT_ID, method_name:"verify_signature", args_base64:argsBase64 }};
  const response = await fetch(NEAR_RPC_URL,{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(json_data)});
  const duration = Date.now()-startTime;
  if(!response.ok){ logger.metric("near_rpc_calls", duration,{result:"failure",method:"verify_signature",status_code:response.status}); throw new Error(`HTTP ${response.status}`);} 
  const parsed = await response.json();
  logger.metric("near_rpc_calls", duration,{result:"success",method:"verify_signature"});
  if(parsed.result && parsed.result.result){ return Buffer.from(parsed.result.result,"base64").toString() === 'true'; }
  return false;
}

module.exports = {
    RODiT,
    PayloadNEP413,
    PayloadNEP413Schema,
    CONSTANTS,
    nearorg_rpc_timestamp,
    nearorg_rpc_tokenfromroditid,
    nearorg_rpc_state,
    nearorg_rpc_tokensfromaccountid,
    nearorg_rpc_fetchpublickeybytes,
    nearorg_rpc_accesskeys,
    nearorg_rpc_rodit_owner,
    nearorg_rpc_getnonce,
    nearorg_rpc_verifysignature,
    nearorg_rpc_listpublicagents
};