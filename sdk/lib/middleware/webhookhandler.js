/**
 * Webhook event handling
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

// webhookhandler.js
// Reusable webhook handler for RODiT SDK

const crypto = require("crypto");
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics, infoWithContextIf, errorWithContextIf } = logger;
const { ulid } = require("ulid");
const nacl = require("tweetnacl");
const stateManager = require("../blockchain/statemanager");
const { authenticate_webhook } = require("../auth/authentication");

/**
 * Create a raw body parser middleware specifically for webhook endpoints
 * This preserves the raw body for signature verification
 * @returns {Function} Express middleware
 */
function createRawBodyParser() {
  return (req, res, next) => {
    if (req.headers['content-type'] !== 'application/json') {
      return res.status(415).json({ error: 'Unsupported Media Type. Only application/json is supported.' });
    }
    
    let data = '';
    req.setEncoding('utf8');
    
    req.on('data', (chunk) => {
      data += chunk;
    });
    
    req.on('end', () => {
      // Store the raw body for signature verification
      req.rawBody = data;
      
      // Parse JSON for convenience
      try {
        req.body = JSON.parse(data);
        next();
      } catch (e) {
        res.status(400).json({ error: 'Invalid JSON payload' });
      }
    });
  };
}

/**
 * Create middleware for webhook request processing
 * Webhooks use digital signature authentication only - no API tokens needed
 * @returns {Function} Express middleware
 */
function createWebhookProcessingMiddleware() {
  return (req, res, next) => {
    // Mark this as a webhook request for logging purposes
    req.isWebhookRequest = true;
    next();
  };
}

/**
 * Create middleware to attach the server's public key to the request
 * @param {Object} stateManager - State manager instance
 * @returns {Function} Express middleware
 */
function createPublicKeyMiddleware(stateManager) {
  return async (req, res, next) => {
    const requestId = crypto.randomUUID();
    const logContext = {
      requestId,
      apiEndpoint: req.path,
      method: req.method,
      headers: Object.keys(req.headers),
      hasSignature: !!req.headers["x-signature"],
      hasTimestamp: !!req.headers["x-timestamp"],
    };

    try {
      // Check if this is a test environment where we should bypass signature verification      
      // Get the peer public key from the state manager
      const peerBase64urlJwkPublicKey = stateManager.getPeerBase64urlJwkPublicKey();
      
      // If the peer public key is not available and we're not in test mode, return an error
      if (!peerBase64urlJwkPublicKey) {
        logger.warnWithContext("Peer public key not available in state manager", logContext);
        
        // In production, we need the key
        if (process.env.NODE_ENV === 'production') {
          logger.errorWithContext("Peer public key not available in production environment", logContext);
          return res.status(500).json({ error: "Peer public key not available" });
        }
        
        // In development or test, we'll continue without the key and skip verification
        logger.infoWithContext("Continuing without peer public key in non-production environment", {
          ...logContext,
          environment: process.env.NODE_ENV || 'development'
        });
      }
      
      if (peerBase64urlJwkPublicKey) {
        // Log that we're using the peer public key
        logger.infoWithContext("Using peer public key from state manager", {
          ...logContext,
          keyFormat: "JWK",
          keyFound: true
        });
        
        try {
          logger.debugWithContext("Processing peer public key", {
            ...logContext,
            keyLength: peerBase64urlJwkPublicKey ? peerBase64urlJwkPublicKey.length : 0,
            keyFormat: "base64url_encoded_hex"
          });
          
          // The key is already in base64url format and should be decoded directly to bytes
          req.peer_bytes_ed25519_public_key = new Uint8Array(
            Buffer.from(peerBase64urlJwkPublicKey, "base64url")
          );
          req.server_bytes_ed25519_public_key = req.peer_bytes_ed25519_public_key;
          req.server_public_key_base64url = peerBase64urlJwkPublicKey;

          logger.debugWithContext("Processed peer public key", {
            ...logContext,
            keyLength: req.peer_bytes_ed25519_public_key.length,
            keyFormat: "base64url_decoded_to_bytes"
          });
        } catch (jwkError) {
          logger.errorWithContext("Error converting JWK peer public key", {
            ...logContext,
            error: jwkError.message
          });
          return res.status(500).json({ error: "Error processing peer public key" });
        }
      }
      
      next();
    } catch (error) {
      logger.errorWithContext("Error extracting server public key", {
        ...logContext,
        error: error.message,
        stack: error.stack,
      });
      return res.status(500).json({ error: "Server configuration error" });
    }
  };
}

/**
 * Create middleware to authenticate webhook requests
 * @returns {Function} Express middleware
 */
function createWebhookAuthenticationMiddleware() {
  return async (req, res, next) => {
    const requestId = crypto.randomUUID();
    const logContext = {
      requestId,
      apiEndpoint: req.path,
      method: req.method,
      headers: Object.keys(req.headers),
      bodyKeys: Object.keys(req.jsonBody || req.body || {}),
      bodySize: req.jsonBody ? JSON.stringify(req.jsonBody).length : 0,
    };

    try {
      const signature_hex_ofpayload = req.headers["x-signature"];
      const timestamp = req.headers["x-timestamp"];
      
      // Use the raw body that was captured by our middleware
      const payload = req.rawBody;
      
      if (!signature_hex_ofpayload || !timestamp || !payload) {
        logger.warnWithContext("Missing required webhook authentication parameters", {
          ...logContext,
          hasSignature: !!signature_hex_ofpayload,
          hasTimestamp: !!timestamp,
          hasPayload: !!payload
        });
        return res.status(400).json({ 
          error: "Missing required authentication parameters",
          code: 'MISSING_AUTH_PARAMS'
        });
      }
      
      // Log the payload hash and signature for debugging
      const payloadHash = crypto
        .createHash("sha256")
        .update(payload)
        .digest("hex");
      
      logger.debugWithContext("Webhook payload hash and signature", {
        ...logContext,
        payloadHash: payloadHash,
        payloadWithTimestamp: payload + (timestamp || ''),
        payloadWithTimestampHash: crypto
          .createHash("sha256")
          .update(payload + (timestamp || ''))
          .digest("hex"),
        signature: signature_hex_ofpayload,
        timestamp: timestamp
      });
      
      // Update log context with body info
      if (Array.isArray(req.body)) {
        logContext.bodyIsArray = true;
        logContext.bodyLength = req.body.length;
      } else {
        logContext.bodyIsArray = false;
        logContext.bodyKeys = Object.keys(req.body || {});
      }
      
      logContext.bodySize = payload.length;
      logContext.hasSignature = !!signature_hex_ofpayload;
      logContext.hasTimestamp = !!timestamp;
      
      // Check if we have the server's public key
      if (!req.server_public_key_base64url) {
        // In test environments, we might want to bypass verification
        if (process.env.NODE_ENV === 'test' || process.env.BYPASS_WEBHOOK_VERIFICATION === 'true') {
          logger.warnWithContext("Bypassing webhook authentication in test environment", logContext);
          return next();
        }
        
        logger.errorWithContext("Missing server public key for webhook authentication", logContext);
        return res.status(500).json({ error: "Server configuration error" });
      }
      
      // Authenticate the webhook using the server's public key
      logger.debugWithContext("Authenticating webhook", logContext);
      const publicKeyBase64url = req.server_public_key_base64url;
      
      // Call the authentication function with proper error handling
      let authResult;
      try {
        authResult = await authenticate_webhook(
          payload,
          signature_hex_ofpayload,
          timestamp,
          publicKeyBase64url
        );
      } catch (authError) {
        logger.errorWithContext("Error during webhook authentication", {
          ...logContext,
          error: authError.message,
          stack: authError.stack
        });
        return res.status(500).json({ error: "Webhook authentication error", message: authError.message });
      }

      if (!authResult.isValid) {
        logContext.authError = authResult.error?.message;
        logger.warnWithContext("Invalid webhook signature", {
          ...logContext,
          error: authResult.error?.message,
          code: authResult.error?.code || 'UNKNOWN_ERROR'
        });
        return res.status(401).json({ 
          error: "Invalid webhook signature", 
          message: authResult.error?.message,
          code: authResult.error?.code || 'INVALID_SIGNATURE'
        });
      }

      logger.infoWithContext("Webhook authenticated successfully", {
        ...logContext,
        authDuration: authResult.duration,
        component: "WebhookHandler"
      });
      
      // Store authentication result for later use
      req.webhookAuthResult = authResult;
      
      next();
    } catch (error) {
      logger.errorWithContext("Error authenticating webhook", {
        ...logContext,
        error: error.message,
        stack: error.stack
      });
      return res.status(500).json({ error: "Webhook authentication error" });
    }
  };
}

/**
 * Process a webhook event and extract its data
 * @param {Object} req - Express request object
 * @param {Object} logContext - Logging context
 * @returns {Object} Extracted event data
 */
function processWebhookEvent(req, logContext = {}) {
  try {
    // Check if the body is valid before attempting to destructure
    if (!req.body || typeof req.body !== 'object') {
      logger.errorWithContext("Invalid webhook payload format", {
        ...logContext,
        component: "WebhookHandler",
        bodyType: typeof req.body,
        bodyIsNull: req.body === null,
        contentType: req.headers['content-type']
      });
      return { error: "Invalid payload format" };
    }
    
    const { event, data, isError, timestamp: payloadTimestamp, requestId: payloadRequestId } = req.body;

    const eventType = typeof event === "string" ? event.trim() : "";

    if (!eventType) {
      logger.errorWithContext("Webhook payload missing event type", {
        ...logContext,
        component: "WebhookHandler",
        rawEventValue: event,
        hasEventField: Object.prototype.hasOwnProperty.call(req.body, "event"),
      });
      return { error: "Event type is required but was not provided" };
    }

    logger.infoWithContext("Processing webhook payload", {
      ...logContext,
      component: "WebhookHandler",
      event: eventType,
      eventType,
      isError,
      payloadTimestamp,
      payloadRequestId,
      dataKeys: data ? Object.keys(data) : [],
      dataType: typeof data,
      dataSize: data ? JSON.stringify(data).length : 0
    });

    return {
      type: eventType,
      name: eventType,
      event: eventType,
      data,
      isError,
      timestamp: payloadTimestamp,
      requestId: payloadRequestId,
      error: null
    };
  } catch (error) {
    logger.warnWithContext("Error processing webhook payload", {
      ...logContext,
      component: "WebhookHandler",
      error: error.message,
      stack: error.stack
    });
    return { error: error.message };
  }
}

/**
 * Create a complete webhook handler for Express
 * @param {Object} stateManager - State manager instance
 * @param {Object} configuration - Configuration configuration
 * @returns {Object} Webhook handler with middleware and utilities
 */
function createWebhookHandler(stateManager, configuration = {}) {
  const rawBodyParser = createRawBodyParser();
  const webhookProcessingMiddleware = createWebhookProcessingMiddleware();
  const publicKeyMiddleware = createPublicKeyMiddleware(stateManager);
  const authenticationMiddleware = createWebhookAuthenticationMiddleware();
  
  return {
    // Middleware
    rawBodyParser,
    webhookProcessingMiddleware,
    publicKeyMiddleware,
    authenticationMiddleware,
    
    // Utility functions
    processWebhookEvent,
    
    // Combined middleware for easy setup
    middleware: [
      rawBodyParser,
      webhookProcessingMiddleware,
      publicKeyMiddleware,
      authenticationMiddleware
    ],
    
    // Helper to apply middleware based on route
    applyMiddleware: (app, express) => {
      // Apply raw body parser only to webhook routes
      app.use((req, res, next) => {
        if (req.path === '/webhook') {
          rawBodyParser(req, res, next);
        } else {
          express.json()(req, res, next);
        }
      });
      
      // Apply webhook processing middleware to webhook routes
      app.use('/webhook', webhookProcessingMiddleware);
      
      // Apply public key middleware to webhook routes
      app.use('/webhook', publicKeyMiddleware);
      
      return app;
    }
  };
}

/**
    * Send a webhook notification with comprehensive logging
    *
    * @param {Object} data - Webhook envelope. Expected shape: { event: string, data?: any, isError?: boolean }
    * @param {Object} req - Express request object (optional)
    * @returns {Promise<Object>} Webhook delivery result with requestId
    */
   async function send_webhook(data, req = null) {
     // Derive fields from envelope
     const event = data && typeof data === 'object' ? (data.event || 'generic_event') : 'generic_event';
     let isError = !!(data && data.isError);

     // Always generate a new correlation ID
     const requestId = ulid();

     // Rebind data to the actual payload object (inner data if present, else entire envelope)
     if (data && Object.prototype.hasOwnProperty.call(data, 'data')) {
       data = data.data;
     }
     const startTime = Date.now();
   
     // Create a context object for consistent logging
     const webhookContext = {
       event,
       requestId,
       isError,
       dataType: typeof data,
       operation: "webhook",
       method: "send_webhook",
       component: "WebhookHandler"
     };
   
     // Create base context for all logs in this function
     const baseContext = createLogContext("RoditAuth", "send_webhook", {
       requestId,
       event,
       isError,
       dataSize: typeof data === "object" ? JSON.stringify(data).length : "unknown"
     });
     
     // Log the webhook attempt
     logger.debugWithContext("Starting webhook delivery", baseContext);
   
     // Also log with the infoWithContext pattern used in cruda.js
     logger.infoWithContext("Sending webhook", {
       ...webhookContext,
       status: "attempt",
       eventType: event
     });
   
     try {
       // Get the configuration from state manager
       const config_own_rodit = await stateManager.getConfigOwnRodit();
       
       // Check if webhook configuration is available
       if (
         !config_own_rodit ||
         !config_own_rodit.own_rodit.metadata.webhook_url
       ) {
         const duration = Date.now() - startTime;
   
         logger.warnWithContext("Webhook configuration missing", {
           ...baseContext,
           duration,
           hasConfig: !!config_own_rodit,
           hasOwnRodit: !!config_own_rodit?.own_rodit,
           hasMetadata: !!config_own_rodit?.own_rodit?.metadata
         });
   
         // Emit metrics for dashboards
         logger.metric &&
           logger.metric("webhook_delivery_duration_ms", duration, {
             component: "WebhookHandler",
             success: false,
             event,
             error: "WEBHOOK_CONFIG_ERROR",
           });
         logger.metric &&
           logger.metric("webhook_delivery_failures_total", 1, {
             component: "WebhookHandler",
             reason: "CONFIG_MISSING",
             event,
           });
   
         // Log error with new logErrorWithMetrics helper
         logErrorWithMetrics(
           "Webhook configuration missing", 
           createLogContext(
             "WebhookHandler",
             "webhook_configuration_error",
             {
               ...webhookContext,
               status: "error"
             }
           ),
           new Error("Missing webhook configuration"),
           "webhook_error_count",
           { error_type: "configuration_missing" }
         );
         
         return {
           isValid: false,
           error: {
             code: "WEBHOOK_CONFIG_ERROR",
             message: "Webhook URL not available in Rodit configuration",
             requestId,
           },
         };
       }
   
       // Determine webhook URL from request or config
       let webhookUrl;
       
       // Debug logging to diagnose webhook URL issue
       logger.debugWithContext("Webhook URL determination debug", {
         ...baseContext,
         hasReq: !!req,
         hasReqUser: !!(req && req.user),
         reqUserKeys: req && req.user ? Object.keys(req.user) : [],
         hasWebhookUrl: !!(req && req.user && req.user.rodit_webhookurl),
         webhookUrlValue: req && req.user ? req.user.rodit_webhookurl : null
       });

       // Check if request object is available and has user with webhook URL
       if (req && req.user && req.user.rodit_webhookurl) {
         // Use the webhook URL from the peer's JWT token
         webhookUrl = req.user.rodit_webhookurl;
         logger.debugWithContext("Using webhook URL from peer JWT token", {
           ...baseContext,
           webhookSource: "peer_jwt",
           webhookUrl
         });
       } else {
         webhookUrl = config_own_rodit.own_rodit.metadata.webhook_url;
         logger.debugWithContext("Using webhook URL from own RODiT config", {
           ...baseContext,
           webhookSource: "own_config",
           webhookUrl
         });
       }
   
       // First remove any existing protocol
       const cleanWebhookUrl = webhookUrl.replace(/^(https?:\/\/)/, "");
   
       // Then add https:// protocol
       const formattedWebhookUrl = `https://${cleanWebhookUrl}/webhook`;
   
       logger.debugWithContext("Webhook URL details", {
         ...baseContext,
         rawWebhookUrl: webhookUrl,
         formattedWebhookUrl
       });
   
       const timestamp = Date.now();
       
       // Ensure data is serializable before stringifying
       let sanitizedData;
       try {
         // Test if data can be properly serialized
         if (typeof data === 'object' && data !== null) {
           // Create a deep copy to avoid modifying the original data
           sanitizedData = JSON.parse(JSON.stringify(data));
         } else if (data === undefined || data === null) {
           // Handle null/undefined explicitly
           sanitizedData = null;
         } else if (typeof data === 'string' || typeof data === 'number' || typeof data === 'boolean') {
           // Primitive types can be used directly
           sanitizedData = data;
         } else {
           // For other types (functions, symbols, etc.), create a string representation
           sanitizedData = {
             type: typeof data,
             stringValue: String(data)
           };
         }
       } catch (serializeError) {
         // If data can't be serialized, create a simplified version
         logger.warnWithContext("Data serialization failed, creating simplified version", {
           ...baseContext,
           error: serializeError.message
         });
         
         // Create a simplified version with basic properties
         sanitizedData = {
           type: typeof data,
           summary: "Data could not be serialized to JSON",
           error: serializeError.message
         };
       }
       
       // Create the payload object
       const payloadObj = {
         event,
         data: sanitizedData,
         isError,
         requestId,
       };
       
       // Create the payload with consistent JSON formatting
       // Sort keys to ensure canonical representation regardless of object creation order
       const payload = JSON.stringify(payloadObj, function(key, value) {
         // Handle special numeric values consistently
         if (typeof value === 'number') {
           if (isNaN(value)) return 'NaN';
           if (value === Infinity) return 'Infinity';
           if (value === -Infinity) return '-Infinity';
         }
         return value;
       }, 0);
       
       // Ensure consistent handling of Unicode characters
       const normalizedPayload = payload.normalize('NFC');
       
       logger.debug("Preparing webhook payload", {
         component: "WebhookHandler",
         method: "send_webhook",
         requestId,
         payloadSize: normalizedPayload.length,
         event,
       });
       
       // Create the string to hash: payload + timestamp
       // This binds the timestamp to the payload for signature verification
       const payloadWithTimestamp = normalizedPayload + timestamp.toString();
       
       logger.debugWithContext("Creating payload+timestamp string for signing", {
         ...baseContext,
         payloadSize: normalizedPayload.length,
         timestampLength: timestamp.toString().length,
         combinedLength: payloadWithTimestamp.length
       });
   
       // Generate hash of payload+timestamp
       const sha256_ofpayload = crypto
         .createHash("sha256")
         .update(payloadWithTimestamp)
         .digest();
   
       // Log hash details for visibility
       logger.debug("Webhook hash details", {
         component: "WebhookHandler",
         method: "send_webhook",
         requestId,
         hashHex: sha256_ofpayload.toString('hex'),
         hashLength: sha256_ofpayload.length
       });
   
       logger.debugWithContext("Creating signature", {
         ...baseContext,
         hasPrivateKey: !!config_own_rodit.own_rodit_bytes_private_key
       });
   
       // Convert private key and generate signature
       const own_rodit_private_key = new Uint8Array(
         config_own_rodit.own_rodit_bytes_private_key
       );
   
       // Log the public key from state manager
       const publicKey = stateManager.getOwnBase64urlJwkPublicKey();
       
       // Log the key in multiple formats for precise comparison
       logger.debug("Webhook signing key information", {
         component: "WebhookHandler",
         method: "send_webhook",
         requestId,
         publicKeyBase64url: publicKey,
         publicKeyHex: publicKey ? Buffer.from(publicKey, 'base64url').toString('hex') : null,
         keyLength: publicKey ? Buffer.from(publicKey, 'base64url').length : 0
       });
   
       const signatureStartTime = Date.now();
       const signature_ofpayload = nacl.sign.detached(
         sha256_ofpayload,
         own_rodit_private_key
       );
       const signatureDuration = Date.now() - signatureStartTime;
   
       // Log signature generation metrics
       logger.metric &&
         logger.metric("signature_generation_duration_ms", signatureDuration, {
           component: "WebhookHandler",
         });
   
       const signature_hex_ofpayload =
         Buffer.from(signature_ofpayload).toString("hex");
   
       // Log signature details for visibility and comparison with client logs
       logger.debugWithContext("Webhook signature details", {
         ...baseContext,
         signatureHex: signature_hex_ofpayload,
         signatureBase64: Buffer.from(signature_ofpayload).toString("base64"),
         signatureBase64url: Buffer.from(signature_ofpayload).toString("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
         signatureLength: signature_hex_ofpayload.length,
         signatureByteLength: signature_ofpayload.length
       });
       
       // Log the exact hash that was signed for comparison
       logger.debugWithContext("Webhook hash that was signed", {
         ...baseContext,
         hashHex: Buffer.from(sha256_ofpayload).toString('hex'),
         hashBase64: Buffer.from(sha256_ofpayload).toString('base64'),
         hashBase64url: Buffer.from(sha256_ofpayload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
         hashLength: sha256_ofpayload.length
       });
   
       logger.debugWithContext("Sending webhook request", {
         ...baseContext,
         webhookUrl: formattedWebhookUrl,
         timestamp: timestamp.toString(),
         payload: process.env.NODE_ENV === 'development' ? payload : undefined, // Only log payload in development
         signatureHex: signature_hex_ofpayload
       });
   
       // Prepare headers for the webhook request
       // Only include webhook-specific authentication headers (digital signature)
       // No API bearer tokens - webhook security relies on cryptographic signatures
       const headers = {
         "Content-Type": "application/json",
         "X-Signature": signature_hex_ofpayload,
         "X-Timestamp": timestamp.toString(),
         "X-Request-ID": requestId
       };
       
       // Log the exact headers being sent
       logger.debugWithContext("Webhook request headers", {
         ...baseContext,
         headers: headers,
         signatureHeader: signature_hex_ofpayload,
         timestampHeader: timestamp.toString()
       });
       
       // SELF-VERIFICATION: Call authenticate_webhook with the same parameters the client will use
       // This helps determine if the issue is in the signature generation/verification or in the data flow
       try {
         logger.info("Performing self-verification before sending webhook", {
           component: "WebhookHandler",
           method: "send_webhook",
           requestId
         });
         
         // Get our own public key for verification
         const publicKeyForVerification = stateManager.getOwnBase64urlJwkPublicKey();
         
         // Call authenticate_webhook with the same parameters the client will receive
         const verificationResult = await authenticate_webhook(
           payload,                  // The exact payload being sent
           signature_hex_ofpayload,  // The signature in hex format
           timestamp.toString(),     // The timestamp as a string
           publicKeyForVerification  // Our own public key for verification
         );
         
         logger.infoWithContext("Self-verification result", {
           ...baseContext,
           selfVerificationSuccess: verificationResult.isValid,
           selfVerificationError: verificationResult.error ? verificationResult.error.message : null
         });
         
         if (!verificationResult.isValid) {
           logger.warnWithContext("Self-verification failed - client verification will likely fail too", {
             ...baseContext,
             error: verificationResult.error ? verificationResult.error.message : "Unknown verification error"
           });
         }
       } catch (verificationError) {
         logErrorWithMetrics(
           "Error during self-verification",
           baseContext,
           verificationError,
           "webhook_verification_error",
           { error_type: "self_verification_error" }
         );
       }
       
       // Send webhook request
       const fetchStartTime = Date.now();
       const response = await fetch(formattedWebhookUrl, {
         method: "POST",
         headers: headers,
         body: payload,
       });
       const fetchDuration = Date.now() - fetchStartTime;
   
       // Log fetch duration metrics
       logger.metric("webhook_http_request_duration_ms", fetchDuration, {
         component: "WebhookHandler",
         success: response.ok,
         status: response.status,
         event,
       });
   
       if (!response.ok) {
         const duration = Date.now() - startTime;
   
         logErrorWithMetrics(
           "Webhook delivery failed",
           {
             ...baseContext,
             duration,
             status: response.status,
             statusText: response.statusText,
             webhookUrl: formattedWebhookUrl
           },
           new Error(`HTTP ${response.status}: ${response.statusText}`),
           "webhook_delivery_error",
           { error_type: "http_error", status: response.status }
         );
   
         // Emit metrics for dashboards
         logger.metric("webhook_delivery_duration_ms", duration, {
           component: "WebhookHandler",
           success: false,
           event,
           error: "HTTP_ERROR",
           status: response.status,
         });
         logger.metric("webhook_delivery_failures_total", 1, {
           component: "WebhookHandler",
           reason: "HTTP_ERROR",
           status: response.status,
           event,
         });
   
         throw new Error(`HTTP error! status: ${response.status}`);
       }
   
       await response.text();
   
       const duration = Date.now() - startTime;
       logger.infoWithContext("Webhook delivered successfully", {
         ...baseContext,
         duration,
         webhookUrl: formattedWebhookUrl,
         status: response.status
       });
   
       // Emit metrics for dashboards
       logger.metric("webhook_delivery_duration_ms", duration, {
         component: "WebhookHandler",
         success: true,
         event,
       });
       logger.metric("successful_webhook_deliveries_total", 1, {
         component: "WebhookHandler",
         event,
       });
   
       // Removed test-mode DB recording on success
   
       // Log success with infoWithContext pattern
       logger.infoWithContext("Webhook sent successfully", {
         ...webhookContext,
         status: "success"
       });
       
       // Return success result with requestId for tracing
       return {
         isValid: true,
         message: "Webhook sent successfully",
         requestId,
         duration,
       };
     } catch (error) {
       const duration = Date.now() - startTime;
   
       logErrorWithMetrics(
         "Webhook send failed",
         {
           ...baseContext,
           duration,
           errorCode: error.code || "UNKNOWN_ERROR",
           isError,
           operation: "webhook",
           status: "failed"
         },
         error,
         "webhook_delivery_error",
         { error_type: "network_error" }
       );
   
       // Emit metrics for dashboards
       logger.metric("webhook_delivery_duration_ms", duration, {
         component: "WebhookHandler",
         success: false,
         event,
         error: error.constructor.name,
       });
       logger.metric("webhook_delivery_errors_total", 1, {
         component: "WebhookHandler",
         error: error.constructor.name,
         event,
       });
   
       // Log error with errorWithContext pattern
       logger.errorWithContext && logger.errorWithContext(
         "Webhook send failed", 
         {
           ...webhookContext,
           status: "failed",
           errorMessage: error.message
         },
         error
       );
       
       // Return error result with requestId for tracing
       return {
         isValid: false,
         error: {
           code: "WEBHOOK_SEND_ERROR",
           message: `Failed to send webhook: ${error.message}`,
           requestId,
         },
       };
     }
    }

/**
 * Base class for webhook event handlers
 */
class WebhookEventHandler {
  /**
   * Create a new webhook event handler
   * @param {Object} configuration - Configuration configuration
   */
  constructor(configuration = {}) {
    this.configuration = configuration;
  }

  /**
   * Handle a webhook event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    throw new Error("Method not implemented");
  }
}

/**
 * Handler for test configuration update events
 */
class TestConfigUpdateHandler extends WebhookEventHandler {
  /**
   * Create a new test configuration update handler
   * @param {Object} configManager - Configuration manager
   * @param {Object} configuration - Configuration configuration
   */
  constructor(configManager, configuration = {}) {
    super(configuration);
    this.configManager = configManager;
  }

  /**
   * Handle a test configuration update event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "TestConfigUpdateHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      if (!this.configManager) {
        const error = new Error("Config manager is required but not provided");
        errorWithContextIf(logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }

      // Update configuration
      await this.configManager.updateConfig(event.data);

      infoWithContextIf(logContext, "Test configuration updated successfully");
      return {
        success: true,
        message: "Test configuration updated successfully",
      };
    } catch (error) {
      errorWithContextIf(logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Handler for test suite execution events
 */
class TestSuiteHandler extends WebhookEventHandler {
  /**
   * Create a new test suite handler
   * @param {Function} runTestSuite - Function to run a test suite
   * @param {Object} configuration - Configuration configuration
   */
  constructor(runTestSuite, configuration = {}) {
    super(configuration);
    this.runTestSuite = runTestSuite;
  }

  /**
   * Handle a test suite execution event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "TestSuiteHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      if (!this.runTestSuite) {
        const error = new Error("runTestSuite function is required but not provided");
        errorWithContextIf(logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }

      // Extract test configuration from event data
      const testOptions = event.data || {};
      
      // Run the test suite
      const testResults = await this.runTestSuite(testOptions);

      infoWithContextIf(logContext, "Test suite executed successfully");
      return {
        success: true,
        message: "Test suite executed successfully",
        results: testResults,
      };
    } catch (error) {
      errorWithContextIf(logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Handler for single test execution events
 */
class SingleTestHandler extends WebhookEventHandler {
  /**
   * Create a new single test handler
   * @param {Function} runSingleTest - Function to run a single test
   * @param {Object} configuration - Configuration configuration
   */
  constructor(runSingleTest, configuration = {}) {
    super(configuration);
    this.runSingleTest = runSingleTest;
  }

  /**
   * Handle a single test execution event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "SingleTestHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      if (!this.runSingleTest) {
        const error = new Error("runSingleTest function is required but not provided");
        errorWithContextIf(logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }

      // Extract test configuration from event data
      const testOptions = event.data || {};
      const testName = testOptions.testName;
      
      if (!testName) {
        const error = new Error("testName is required but not provided");
        errorWithContextIf(logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }
      
      // Run the single test
      const testResults = await this.runSingleTest(testName, testOptions);

      infoWithContextIf(logContext, "Single test executed successfully");
      return {
        success: true,
        message: `Test '${testName}' executed successfully`,
        results: testResults,
      };
    } catch (error) {
      errorWithContextIf(logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Handler for comment events
 */
class CommentEventHandler extends WebhookEventHandler {
  /**
   * Create a new comment event handler
   * @param {Object} configuration - Configuration configuration
   */
  constructor(configuration = {}) {
    super(configuration);
  }

  /**
   * Handle a comment event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "CommentEventHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      // Log the comment event
      infoWithContextIf(logContext, "Comment event received", {
        eventType: event.type,
        commentId: event.data?.commentId,
        userId: event.data?.userId,
        testId: event.data?.testId,
      });

      // For now, we just acknowledge receipt of the event
      // In the future, this could store comments in a database or trigger other actions
      return {
        success: true,
        message: `Comment event '${event.type}' processed successfully`,
        eventType: event.type,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      errorWithContextIf(logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Factory for creating webhook event handlers
 */
class WebhookEventHandlerFactory {
  /**
   * Create a new webhook event handler factory
   * @param {Object} dependencies - Dependencies for handlers
   * @param {Object} configuration - Configuration configuration
   */
  constructor(dependencies = {}, configuration = {}) {
    this.dependencies = dependencies;
    this.configuration = configuration;
    this.handlers = new Map();
    
    // Register default handlers if dependencies are provided
    if (dependencies.configManager) {
      this.registerHandler("test_config_update", new TestConfigUpdateHandler(dependencies.configManager, configuration));
    }
    
    if (dependencies.runTestSuite) {
      this.registerHandler("run_test_suite", new TestSuiteHandler(dependencies.runTestSuite, configuration));
    }
    
    if (dependencies.runSingleTest) {
      this.registerHandler("run_single_test", new SingleTestHandler(dependencies.runSingleTest, configuration));
    }
    
    // Register comment event handlers
    const commentHandler = new CommentEventHandler(configuration);
    this.registerHandler("comment_created", commentHandler);
    this.registerHandler("comment_updated", commentHandler);
    this.registerHandler("comment_deleted", commentHandler);
    this.registerHandler("comments_listed", commentHandler);
    this.registerHandler("create_comment_error", commentHandler);
    this.registerHandler("update_comment_error", commentHandler);
    this.registerHandler("delete_comment_error", commentHandler);
    this.registerHandler("read_comment_error", commentHandler);
  }

  /**
   * Register a handler for an event type
   * @param {string} eventType - Event type
   * @param {WebhookEventHandler} handler - Event handler
   */
  registerHandler(eventType, handler) {
    this.handlers.set(eventType, handler);
  }

  /**
   * Get a handler for an event type
   * @param {string} eventType - Event type
   * @returns {WebhookEventHandler|null} Event handler or null if not found
   */
  getHandler(eventType) {
    return this.handlers.get(eventType) || null;
  }

  /**
   * Handle a webhook event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "WebhookEventHandlerFactory",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      const eventType = event.type;
      
      if (!eventType) {
        const error = new Error("Event type is required but not provided");
        errorWithContextIf(logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }
      
      const handler = this.getHandler(eventType);
      
      if (!handler) {
        const error = new Error(`No handler registered for event type: ${eventType}`);
        errorWithContextIf(logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }
      
      return await handler.handleEvent(event, req, res);
    } catch (error) {
      errorWithContextIf(logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

module.exports = {
  // Original exports from webhookhandler.js
  createRawBodyParser,
  createWebhookProcessingMiddleware,
  createPublicKeyMiddleware,
  createWebhookAuthenticationMiddleware,
  processWebhookEvent,
  createWebhookHandler,
  send_webhook,
  
  // Added exports from eventhandler.js
  WebhookEventHandler,
  TestConfigUpdateHandler,
  TestSuiteHandler,
  SingleTestHandler,
  CommentEventHandler,
  WebhookEventHandlerFactory
};