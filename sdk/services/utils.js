/**
 * Utility functions for RODiT Authentication
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const { createLogContext, logErrorWithMetrics } = require("./logger");
const logger = require("./logger");
const bs58 = require("bs58");
const nacl = require("tweetnacl");
nacl.util = require("tweetnacl-util");
const { decodeUTF8 } = require("tweetnacl-util");

// Dynamic import for ESM 'jose' in CommonJS context
let _josePromise;
async function getJose() {
  if (!_josePromise) {
    _josePromise = import("jose");
  }
  return _josePromise;
}

/**
 * Test-specific fetch with error handling for API calls
 * This function is specifically designed for test modules and should not be confused with SDK HTTP methods
 * @param {string} url - URL to fetch
 * @param {Object} fetchoptions - Fetch fetchoptions
 * @returns {Promise<Object>} - Response data
 */
async function testFetchWithErrorHandling(url, fetchoptions = {}) {
  const requestId = ulid();
  const startTime = Date.now();
  
  try {
    // Debug: Log headers being sent
    const finalHeaders = {
      "Content-Type": "application/json",
      ...fetchoptions.headers
    };
    
    logger.debug(`Test fetch: ${url}`, {
      component: "TestFetchHandler",
      requestId,
      url,
      method: fetchoptions.method || "GET",
      hasAuthHeader: !!finalHeaders.Authorization,
      authHeaderValue: finalHeaders.Authorization ? finalHeaders.Authorization.substring(0, 20) + '...' : 'none',
      allHeaders: Object.keys(finalHeaders)
    });

    logger.info(`API request initiated`, {
      component: "APIClient",
      method: "fetchWithErrorHandling",
      requestId,
      url: url.split('/').pop(), // Just the endpoint part
      operation: fetchoptions.method || "GET",
      retryCount: 0
    });

    const response = await fetch(url, {
      ...fetchoptions,
      headers: finalHeaders
    });

    const duration = Date.now() - startTime;
    
    if (!response.ok) {
      const errorText = await response.text();
      
      logger.error(`Test fetch error: ${response.status} ${response.statusText}`, {
        component: "TestFetchHandler",
        requestId,
        url,
        method: fetchoptions.method || "GET",
        status: response.status,
        statusText: response.statusText,
        duration,
        errorText
      });
      
      throw new Error(`HTTP error ${response.status}: ${errorText}`);
    }
    
    const data = await response.json();
    
    logger.info(`API request completed`, {
      component: "APIClient",
      method: "fetchWithErrorHandling",
      requestId,
      url: url.split('/').pop(), // Just the endpoint part
      statusCode: response.status,
      duration
    });
    
    return data;
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error(`Test fetch exception: ${error.message}`, {
      component: "TestFetchHandler",
      requestId,
      url,
      method: fetchoptions.method || "GET",
      duration,
      error: error.message,
      stack: error.stack
    });
    
    throw error;
  }
}

/**
 * Converts a date string to Unix timestamp
 *
 * @param {string} datestring - Date string in ISO format
 * @returns {Promise<number>} Unix timestamp in seconds
 */
async function dateStringToUnixTime(datestring) {
  const date = new Date(datestring);
  const unixTimeMs = date.getTime();
  const unixTimeSec = Math.floor(unixTimeMs / 1000);
  return unixTimeSec;
}

/**
 * Converts a Unix timestamp to a date string
 * This function is used by both the API and test suite
 *
 * @param {number|string} unixTimeSec - Unix timestamp in seconds
 * @returns {Promise<string>} Date string in ISO format
 */
async function unixTimeToDateString(unixTimeSec) {
  const unixTimeMs = unixTimeSec * 1000;
  const date = new Date(unixTimeMs);
  return date.toISOString();
}

/**
 * Ensures a URL has a protocol prefix (http:// or https://)
 * @param {string} url - URL to ensure has a protocol
 * @returns {string} URL with protocol prefix
 */
function ensureProtocol(url) {
  if (!url) {
    logger.warn("Empty URL provided to ensureProtocol", {
      component: "Utils",
      function: "ensureProtocol",
    });
    return "";
  }

  if (url.startsWith("http://") || url.startsWith("https://")) {
    return url;
  }

  return "https://" + url;
}

/**
 * Converts base64 to base64url format
 *
 * @param {string} base64 - Base64 string
 * @returns {string} Base64url string
 */
function base64ToBase64Url(base64) {
  const result = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  logger.debug("Converting base64 to base64url", {
    component: "Transformer",
    method: "base64ToBase64Url",
    inputLength: base64.length,
    outputLength: result.length,
  });

  return result;
}

/**
 * Canonicalizes an object for consistent hash generation
 *
 * @param {Object|Array|any} obj - Object to canonicalize
 * @returns {Object|Array|any} Canonicalized object
 */
function canonicalizeObject(obj) {
  const startTime = Date.now();
  const requestId = ulid();

  logger.debug("Starting object canonicalization", {
    component: "Transformer",
    method: "canonicalizeObject",
    requestId,
    objectType:
      obj === null ? "null" : Array.isArray(obj) ? "array" : typeof obj,
  });

  if (typeof obj !== "object" || obj === null) {
    // Commented out unnecessary canonicalization logging
    // logger.info("Skipping canonicalization for non-object", {
    //   component: "Transformer",
    //   method: "canonicalizeObject",
    //   requestId,
    //   valueType: typeof obj,
    // });
    return obj;
  }

  let result;
  if (Array.isArray(obj)) {
    logger.debug("Canonicalizing array", {
      component: "Transformer",
      method: "canonicalizeObject",
      requestId,
      arrayLength: obj.length,
    });
    result = obj.map(canonicalizeObject);
  } else {
    logger.debug("Canonicalizing object", {
      component: "Transformer",
      method: "canonicalizeObject",
      requestId,
      keyCount: Object.keys(obj).length,
    });
    result = Object.fromEntries(
      Object.entries(obj)
        .sort()
        .map(([key, value]) => [key, canonicalizeObject(value)])
    );
  }

  const duration = Date.now() - startTime;
  logger.debug("Object canonicalization complete", {
    component: "Transformer",
    method: "canonicalizeObject",
    requestId,
    duration,
  });

  // Emit metrics for dashboards if operation took significant time
  if (duration > 50) {
    logger.metric("canonicalization_duration_ms", duration, {
      component: "Transformer",
      objectType: Array.isArray(obj) ? "array" : "object",
      size: Array.isArray(obj) ? obj.length : Object.keys(obj).length,
    });
  }

  return result;
}

/**
 * Calculates a canonical hash for an object
 *
 * @param {Object|Array|any} variable - Variable to hash
 * @returns {string} Hex hash string
 */
function calculateCanonicalHash(variable) {
  const startTime = Date.now();
  const requestId = ulid();

  logger.debug("Calculating canonical hash", {
    component: "Transformer",
    method: "calculateCanonicalHash",
    requestId,
    variableType: typeof variable,
  });

  try {
    const canonicalObj = canonicalizeObject(variable);
    const canonicalJson = JSON.stringify(canonicalObj);

    logger.debug("Canonicalized JSON created", {
      component: "Transformer",
      method: "calculateCanonicalHash",
      requestId,
      jsonLength: canonicalJson.length,
    });

    const messageUint8 = decodeUTF8(canonicalJson);

    logger.debug("Decoded to Uint8Array for hashing", {
      component: "Transformer",
      method: "calculateCanonicalHash",
      requestId,
      bytesLength: messageUint8.length,
    });

    const hashUint8 = nacl.hash(messageUint8);

    logger.debug("Hash calculated", {
      component: "Transformer",
      method: "calculateCanonicalHash",
      requestId,
      hashLength: hashUint8.length,
    });

    const hexResult = Array.from(hashUint8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const duration = Date.now() - startTime;
    logger.debug("Canonical hash calculation complete", {
      component: "Transformer",
      method: "calculateCanonicalHash",
      requestId,
      duration,
      hashLength: hexResult.length,
    });

    // Emit metrics for dashboards
    logger.metric("hash_calculation_duration_ms", duration, {
      component: "Transformer",
      jsonLength: canonicalJson.length,
    });

    return hexResult;
  } catch (error) {
    const duration = Date.now() - startTime;

    logger.error("Hash calculation failed", {
      component: "Transformer",
      method: "calculateCanonicalHash",
      requestId,
      duration,
      errorMessage: error.message,
      stack: error.stack,
    });

    // Emit metrics for dashboards
    logger.metric("hash_calculation_duration_ms", duration, {
      component: "Transformer",
      success: false,
      error: error.constructor.name,
    });
    logger.metric("hash_calculation_errors_total", 1, {
      component: "Transformer",
      errorType: error.constructor.name,
    });

    throw error;
  }
}

/**
 * Validates and sets a URL value
 *
 * @param {string} value - URL to validate
 * @param {string} field - Field name for error messages
 * @param {Object} obj - Object to set the value on
 * @returns {string|null} Validated URL or null if invalid
 */
const validateAndSetUrl = (value, field, obj = null) => {
  const requestId = ulid();
  const startTime = Date.now();

  logger.debug("Validating URL", {
    component: "Validator",
    method: "validateAndSetUrl",
    requestId,
    field,
  });

  if (value == null) {
    logger.debug("URL validation skipped, value is null", {
      component: "Validator",
      method: "validateAndSetUrl",
      requestId,
      field,
    });
    return null;
  }

  // First remove any existing protocol
  let normalizedUrl = value.replace(/^(https?:\/\/)/, "");

  // Remove whitespace for testing
  const testUrl = normalizedUrl.replace(/\s+/g, "");

  // Updated regex to properly handle ports and domain names
  const urlRegex =
    /^(localhost(:[0-9]{1,5})?|([\da-z][\da-z-]*[\da-z]\.)*[\da-z][\da-z-]*[\da-z]\.[a-z\.]{2,6}(:[0-9]{1,5})?|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:[0-9]{1,5})?)(\/[\w\.-]*)*\/?$/i;

  if (urlRegex.test(testUrl)) {
    const result = `https://${normalizedUrl}`;

    const duration = Date.now() - startTime;
    logger.debug("URL validation successful", {
      component: "Validator",
      method: "validateAndSetUrl",
      requestId,
      field,
      duration,
      isValid: true,
    });

    // Emit metrics for dashboards
    logger.metric("validation_duration_ms", duration, {
      validationType: "url",
      field,
      success: true,
      component: "Validator",
    });

    if (obj && typeof obj === "object") {
      obj[field] = result;
    }
    return result;
  }

  const duration = Date.now() - startTime;
  logger.warn("URL validation failed", {
    component: "Validator",
    method: "validateAndSetUrl",
    requestId,
    field,
    duration,
    isValid: false,
    value,
  });

  // Emit metrics for dashboards
  logger.metric("validation_duration_ms", duration, {
    validationType: "url",
    field,
    success: false,
    component: "Validator",
  });
  logger.metric("validation_errors_total", 1, {
    validationType: "url",
    field,
    component: "Validator",
  });

  throw new Error(`Invalid URL for ${field}: ${value}`);
};

/**
 * Validates and sets a date value
 *
 * @param {string} value - Date to validate
 * @param {string} field - Field name for error messages
 * @param {Object} obj - Object to set the value on
 * @returns {string} Validated date string
 */
const validateAndSetDate = (value, field, obj = null) => {
  const requestId = ulid();
  const startTime = Date.now();

  logger.debug("Validating date", {
    component: "Validator",
    method: "validateAndSetDate",
    requestId,
    field,
    value,
  });

  if (value == null || value === "0" || value === "") {
    logger.debug("Date validation defaulted to 1970-01-01", {
      component: "Validator",
      method: "validateAndSetDate",
      requestId,
      field,
      reason: "Empty or null value",
    });
    const defaultDate = "1970-01-01";

    if (obj && typeof obj === "object") {
      obj[field] = defaultDate;
    }
    return defaultDate;
  }

  const date = new Date(value);
  if (isNaN(date.getTime()) || date < new Date("1970-01-01")) {
    const duration = Date.now() - startTime;
    logger.warn("Date validation failed", {
      component: "Validator",
      method: "validateAndSetDate",
      requestId,
      field,
      duration,
      isValid: false,
      value,
      reason: isNaN(date.getTime())
        ? "Invalid date format"
        : "Date before 1970-01-01",
    });

    // Emit metrics for dashboards
    logger.metric("validation_duration_ms", duration, {
      validationType: "date",
      field,
      success: false,
      component: "Validator",
    });
    logger.metric("validation_errors_total", 1, {
      validationType: "date",
      field,
      component: "Validator",
      reason: isNaN(date.getTime()) ? "invalid_format" : "before_epoch",
    });

    throw new Error(
      `Invalid date for ${field}: ${value}. Must be YYYY-MM-DD and no earlier than 1970-01-01`
    );
  }

  const duration = Date.now() - startTime;
  logger.debug("Date validation successful", {
    component: "Validator",
    method: "validateAndSetDate",
    requestId,
    field,
    duration,
    isValid: true,
  });

  // Emit metrics for dashboards
  logger.metric("validation_duration_ms", duration, {
    validationType: "date",
    field,
    success: true,
    component: "Validator",
  });

  if (obj && typeof obj === "object") {
    obj[field] = value;
  }
  return value;
};

/**
 * Validates and sets a JSON value
 *
 * @param {string|Object} value - JSON string or object to validate
 * @param {string} field - Field name for error messages
 * @param {Object} obj - Object to set the value on
 * @returns {string|null} Validated JSON string or null
 */
const validateAndSetJson = (value, field, obj = null) => {
  const requestId = ulid();
  const startTime = Date.now();

  logger.debug("Validating JSON", {
    component: "Validator",
    method: "validateAndSetJson",
    requestId,
    field,
  });

  if (value == null) {
    logger.debug("JSON validation skipped, value is null", {
      component: "Validator",
      method: "validateAndSetJson",
      requestId,
      field,
    });
    return null;
  }

  let jsonString;
  try {
    if (typeof value === "object") {
      jsonString = JSON.stringify(value);
      logger.debug("Converted object to JSON string", {
        component: "Validator",
        method: "validateAndSetJson",
        requestId,
        field,
        objectType: value.constructor.name,
      });
    } else if (typeof value === "string") {
      JSON.parse(value); // Just to validate, we don't use the result
      jsonString = value;
      logger.debug("Validated JSON string", {
        component: "Validator",
        method: "validateAndSetJson",
        requestId,
        field,
      });
    } else {
      const duration = Date.now() - startTime;
      logger.warn("JSON validation failed - invalid type", {
        component: "Validator",
        method: "validateAndSetJson",
        requestId,
        field,
        duration,
        actualType: typeof value,
        isValid: false,
      });

      // Emit metrics for dashboards
      logger.metric("validation_duration_ms", duration, {
        validationType: "json",
        field,
        success: false,
        component: "Validator",
        reason: "invalid_type",
      });
      logger.metric("validation_errors_total", 1, {
        validationType: "json",
        field,
        component: "Validator",
        reason: "invalid_type",
      });

      throw new Error(`Invalid type for ${field}: ${typeof value}`);
    }
  } catch (e) {
    const duration = Date.now() - startTime;
    logger.warn("JSON validation failed - parsing error", {
      component: "Validator",
      method: "validateAndSetJson",
      requestId,
      field,
      duration,
      errorMessage: e.message,
      isValid: false,
      valuePreview: typeof value === "string" ? value.substring(0, 100) : null,
    });

    // Emit metrics for dashboards
    logger.metric("validation_duration_ms", duration, {
      validationType: "json",
      field,
      success: false,
      component: "Validator",
      reason: "parse_error",
    });
    logger.metric("validation_errors_total", 1, {
      validationType: "json",
      field,
      component: "Validator",
      reason: "parse_error",
    });

    throw new Error(`Invalid JSON for ${field}: ${e.message}`);
  }

  const duration = Date.now() - startTime;
  logger.debug("JSON validation successful", {
    component: "Validator",
    method: "validateAndSetJson",
    requestId,
    field,
    duration,
    isValid: true,
    jsonLength: jsonString.length,
  });

  // Emit metrics for dashboards
  logger.metric("validation_duration_ms", duration, {
    validationType: "json",
    field,
    success: true,
    component: "Validator",
  });

  if (obj && typeof obj === "object") {
    obj[field] = jsonString;
  }
  return jsonString;
};

/**
 * Validates and extracts credentials from parsed data
 *
 * @param {Object} parsedData - The parsed credential data
 * @param {Object} logger - Logger instance
 * @returns {Object} The validated and extracted credentials
 * @throws {Error} If the credential data is invalid
 */
function validateAndExtractCredentials(parsedData, logger) {
  const requestId = ulid();
  const context = createLogContext("CredentialManager", "validateAndExtractCredentials", { requestId });
  
  if (logger && logger.debugWithContext) {
    logger.debugWithContext("Validating credential data", context);
  }

  const { implicit_account_id, private_key, public_key } = parsedData;

  // Validate required fields
  if (!implicit_account_id || typeof implicit_account_id !== "string") {
    throw new Error("Error 244: Invalid or missing implicit_account_id value");
  }

  if (!private_key || typeof private_key !== "string") {
    throw new Error("Error 043: Invalid or missing private_key value");
  }

  // Process private key
  const privateKeyStr = stripEd25519Prefix(private_key);
  const signing_bytes_key = new Uint8Array(bs58.decode(privateKeyStr));

  // Log key processing
  if (logger && logger.debugWithContext) {
    logger.debugWithContext("Processed credentials", {
      ...context,
      accountId: implicit_account_id,
      keyLength: privateKeyStr.length,
      isUint8Array: true
    });
  }

  return {
    account_id: implicit_account_id,
    implicit_account_id,
    private_key: privateKeyStr,
    signing_bytes_key
  };
}

/**
 * Strips the 'ed25519:' prefix from a key if present
 *
 * @param {string} key - The key to strip the prefix from
 * @returns {string} The key without the 'ed25519:' prefix
 * @throws {Error} If the key is not a string or is empty
 */
function stripEd25519Prefix(key) {
  const requestId = ulid();

  // Create a base context for this method
  const baseContext = createLogContext("Utils", "stripEd25519Prefix", {
    requestId,
    keyType: typeof key,
    hasPrefix: key && typeof key === "string" && key.startsWith("ed25519:"),
  });

  logger.debugWithContext("Stripping ed25519 prefix from key", baseContext);

  if (!key || typeof key !== "string") {
    const error = new Error("Error 053: Invalid key format");
    logErrorWithMetrics(
      "Invalid key format for prefix stripping",
      baseContext,
      error,
      "key_processing_error",
      { error_type: "invalid_key_format" }
    );
    throw error;
  }

  return key.replace("ed25519:", "");
}

/**
 * Converts a public key to an implicit account ID according to NEAR protocol
 *
 * @param {string} publicKey - The public key to convert (with or without ed25519: prefix)
 * @param {string} outputFormat - The output format ('hex' or 'base58')
 * @returns {string} The implicit account ID
 * @throws {Error} If the public key is invalid or conversion fails
 */
function publicKeyToImplicitId(publicKey, outputFormat = "hex") {
  const requestId = ulid();

  // Create a base context for this method
  const baseContext = createLogContext("Utils", "publicKeyToImplicitId", {
    requestId,
    keyType: typeof publicKey,
    outputFormat,
  });

  logger.debugWithContext("Converting public key to implicit ID", baseContext);

  if (!publicKey || typeof publicKey !== "string") {
    const error = new Error("Error 054: Invalid public key format");
    logErrorWithMetrics(
      "Invalid public key format",
      baseContext,
      error,
      "key_processing_error",
      { error_type: "invalid_public_key_format" }
    );
    throw error;
  }

  try {
    // Use the shared implementation from utils.js
    const keyWithoutPrefix = stripEd25519Prefix(publicKey);

    // Decode the base58 public key
    const publicKeyBytes = bs58.decode(keyWithoutPrefix);

    // The first byte is the key type (0xED for ed25519), the rest is the actual key
    const publicKeyData = publicKeyBytes.slice(1);

    // Convert to the requested output format
    let result;
    if (outputFormat === "hex") {
      result = Buffer.from(publicKeyData).toString("hex");
    } else if (outputFormat === "base58") {
      result = bs58.encode(publicKeyData);
    } else {
      throw new Error(`Unsupported output format: ${outputFormat}`);
    }

    logger.debugWithContext(
      "Successfully converted public key to implicit ID",
      {
        ...baseContext,
        outputFormat,
        idLength: result.length,
      }
    );

    return result;
  } catch (error) {
    logErrorWithMetrics(
      "Error converting public key to implicit ID",
      baseContext,
      error,
      "key_processing_error",
      { error_type: "conversion_error" }
    );
    throw error;
  }
}

/**
 * Converts a base64url string to a base64 string
 *
 * @param {string} base64url - Base64url string
 * @returns {string} Base64 string
 */
function base64urlToBase64(base64url) {
  return base64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(base64url.length + ((4 - (base64url.length % 4)) % 4), "=");
}

/**
 * Converts a base64url encoded public key to a JWK (JSON Web Key) format
 *
 * @param {string} base64url_public_key - Base64url encoded public key
 * @returns {Object} JWK formatted public key using jose's importJWK
 */
async function base64url2jwk_public_key(base64url_public_key) {
  try {
    // Check if the input is a valid base64url string
    const validBase64UrlRegex = /^[A-Za-z0-9_-]*$/;
    const isValidFormat = validBase64UrlRegex.test(base64url_public_key);

    // Create the JWK object
    const jwk_public_key = {
      kty: "OKP",
      crv: "Ed25519",
      x: base64url_public_key,
      use: "sig",
    };
    // Let's also try to decode the base64url to see if it's the right length for Ed25519
    try {
      const bytes = bufferUtils.base64urlToUint8Array(base64url_public_key);
      // Validate bytes length silently
    } catch (decodeError) {
      logger.error("[base64url2jwk_public_key] Error decoding base64url");
    }

    // Import the JWK
    const { importJWK } = await getJose();
    const session_jwk_public_key = await importJWK(jwk_public_key, "EdDSA");
    return session_jwk_public_key;
  } catch (error) {
    logger.errorWithContext(
      "[base64url2jwk_public_key] Error",
      { message: error.message },
      error
    );
    throw error;
  }
}


/**
 * Buffer utility functions for data conversion
 */
const bufferUtils = {
  /**
   * Converts a hex string to Uint8Array
   *
   * @param {string} hexString - Hex string to convert
   * @returns {Uint8Array} Converted bytes
   */
  hexToUint8Array: (hexString) => {
    const matches = hexString.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
  },

  /**
   * Converts a base64url string to Uint8Array
   *
   * @param {string} base64url - Base64url string to convert
   * @returns {Uint8Array} Converted bytes
   */
  base64urlToUint8Array: (base64url) => {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(
      base64.length + ((4 - (base64.length % 4)) % 4),
      "="
    );
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  /**
   * Converts a Uint8Array to base64url string
   *
   * @param {Uint8Array} uint8Array - Bytes to convert
   * @returns {string} Base64url string
   */
  uint8ArrayToBase64url: (uint8Array) => {
    const binary = String.fromCharCode(...uint8Array);
    const base64 = btoa(binary);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  },
};

/**
 * Checks if a subscription is active based on token metadata dates
 *
 * @param {Object} metadata - Token metadata with not_before and not_after dates
 * @returns {boolean} True if subscription is active
 */
// isSubscriptionActive has been moved to RoditClient class

/**
 * Validates if a string is a valid CIDR IP range
 *
 * @param {string} cidr - CIDR notation IP range to validate
 * @returns {boolean} True if valid CIDR range
 */
function isValidIpRange(cidr) {
  if (!cidr || typeof cidr !== "string") return false;

  // Simple CIDR validation regex
  const cidrRegex =
    /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/;
  return cidrRegex.test(cidr);
}

// isValidEndpoint function removed - endpoint comes from RODiT token and is correct by definition

/**
 * Parses a JSON string safely with fallback to default value
 *
 * @param {string} json - JSON string to parse
 * @param {Object} defaultValue - Default value if parsing fails
 * @returns {Object} Parsed JSON or default value
 */
function parseMetadataJson(json, defaultValue = {}) {
  if (!json || typeof json !== "string") return defaultValue;

  try {
    return JSON.parse(json);
  } catch (e) {
    return defaultValue;
  }
}

module.exports = {
  base64url2jwk_public_key,
  base64urlToBase64,
  calculateCanonicalHash,
  canonicalizeObject,
  dateStringToUnixTime,
  ensureProtocol,
  isValidIpRange,
  parseMetadataJson,
  publicKeyToImplicitId,
  testFetchWithErrorHandling,
  unixTimeToDateString,
  validateAndExtractCredentials,
  validateAndSetDate,
  validateAndSetJson,
  validateAndSetUrl,
};
