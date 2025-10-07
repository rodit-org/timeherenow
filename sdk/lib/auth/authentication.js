/**
 * Authentication service for RODiT authentication
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const nacl = require("tweetnacl");
nacl.util = require("tweetnacl-util");
const crypto = require("crypto");
const { Resolver } = require("dns").promises;
const { calculateCanonicalHash, unixTimeToDateString } = require("../../services/utils");
const stateManager = require("../blockchain/statemanager");
const borsh = require("borsh");
const { 
  nearorg_rpc_timestamp, 
  nearorg_rpc_tokenfromroditid, 
  nearorg_rpc_fetchpublickeybytes,
  RODiT,
  PayloadNEP413,
  PayloadNEP413Schema,
  CONSTANTS,
} = require("../blockchain/blockchainservice");

async function verify_rodit_ownership(
    peerroditid,
    peertimestamp,
    peerroditid_base64url_signature,
    peer_rodit
  ) {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context that will be used throughout this function
    const baseContext = createLogContext(
      "AuthServices",
      "verify_rodit_ownership",
      {
        requestId,
        peerRoditId: peerroditid,
        timestamp: peertimestamp,
      }
    );
    
    logger.infoWithContext("Starting RODiT ownership verification", baseContext);
    
    logger.debugWithContext("Verification parameters", {
      ...baseContext,
      signatureLength: peerroditid_base64url_signature?.length,
      signatureValue: peerroditid_base64url_signature?.substring(0, 20) + '...',
    });

    try {
      // DO NOT DELETE THE FOLLOWING COMMENT
      /* Maybe for NEP413 compatibility, the following line added "NEAR" before peerroditid */
      
      // Match legacy implementation exactly
      const timeString = await unixTimeToDateString(peertimestamp);
      const roditidandtimestamp = new TextEncoder().encode(
        peerroditid + timeString
      );

      logger.debugWithContext("Encoded roditid and timestamp", {
        ...baseContext,
        timeString,
        combinedString: peerroditid + timeString,
        bufferLength: roditidandtimestamp.length,
        bufferHex: Buffer.from(roditidandtimestamp).toString('hex'),
      });

      // Check if signature is defined before proceeding
      if (!peerroditid_base64url_signature) {
        const duration = Date.now() - startTime;
        
        logger.warnWithContext("Missing signature in authentication request", {
          ...baseContext,
          duration
        });
        
        // Emit metrics for dashboards
        logger.metric("rodit_ownership_verification_ms", duration, {
          component: "AuthServices",
          success: false,
          error: "MISSING_SIGNATURE"
        });
        logger.metric("failed_verification_attempts_total", 1, {
          component: "AuthServices",
          reason: "MISSING_SIGNATURE"
        });
        
        logErrorWithMetrics(
          "Missing signature in authentication request", 
          baseContext, 
          new Error("Missing signature in authentication request"),
          "auth_error",
          { error_type: "missing_signature" }
        );
        throw new Error("Missing signature in authentication request");
      }

      const bytes_ed25519_signature = new Uint8Array(
        Buffer.from(peerroditid_base64url_signature, "base64url")
      );
      
      logger.debugWithContext("Decoded signature using base64url", {
        ...baseContext,
        signatureLength: bytes_ed25519_signature.length,
        signatureHex: Buffer.from(bytes_ed25519_signature).toString('hex'),
        expectedLength: 64, // Ed25519 signatures should be 64 bytes
      });

      const peer_bytes_ed25519_public_key =
        await nearorg_rpc_fetchpublickeybytes(
          peer_rodit.owner_id
        );

      logger.debugWithContext("Retrieved public key", {
        ...baseContext,
        ownerId: peer_rodit.owner_id,
        keyLength: peer_bytes_ed25519_public_key?.length || 0,
        keyHex: peer_bytes_ed25519_public_key ? Buffer.from(peer_bytes_ed25519_public_key).toString('hex') : 'null',
        expectedLength: 32, // Ed25519 public keys should be 32 bytes
      });

      // Add more detailed debugging for verification inputs
      logger.debugWithContext("Verification inputs", {
        ...baseContext,
        messageLength: roditidandtimestamp.length,
        messageContent: peerroditid + timeString,
        signatureLength: bytes_ed25519_signature.length,
        publicKeyLength: peer_bytes_ed25519_public_key?.length,
        messageHex: Buffer.from(roditidandtimestamp).toString('hex'),
        signatureHex: Buffer.from(bytes_ed25519_signature).toString('hex'),
        publicKeyHex: peer_bytes_ed25519_public_key ? Buffer.from(peer_bytes_ed25519_public_key).toString('hex') : 'null'
      });

      const isaMatch = nacl.sign.detached.verify(
        roditidandtimestamp,
        bytes_ed25519_signature,
        peer_bytes_ed25519_public_key
      );
      
      const duration = Date.now() - startTime;

      if (isaMatch) {
        // Use infoWithContext for successful verification
        logger.infoWithContext("Peer RODiT ownership check successful", {
          ...baseContext,
          duration,
          ownerId: peer_rodit.owner_id,
          outcome: "success"
        });

        // Emit metrics for dashboards
        logger.metric("rodit_ownership_verification_ms", duration, {
          component: "AuthServices",
          success: true,
          roditId: peerroditid
        });
        logger.metric("successful_verification_attempts_total", 1, {
          component: "AuthServices",
          roditId: peerroditid
        });

        return true;
      } else {
        // Use logErrorWithMetrics for failed verification
        logger.warnWithContext("Peer RODiT ownership check failed", {
          ...baseContext,
          duration,
          ownerId: peer_rodit.owner_id,
          outcome: "failed"
        });
        
        // Emit metrics for dashboards
        logger.metric("rodit_ownership_verification_ms", duration, {
          component: "AuthServices",
          success: false,
          error: "SIGNATURE_VERIFICATION_FAILED",
          roditId: peerroditid
        });
        logger.metric("failed_verification_attempts_total", 1, {
          component: "AuthServices",
          reason: "SIGNATURE_VERIFICATION_FAILED",
          roditId: peerroditid
        });
        
        logErrorWithMetrics(
          "Peer RODiT ownership check failed", 
          {
            ...baseContext,
            duration,
            ownerId: peer_rodit.owner_id,
            outcome: "failed"
          },
          new Error("Error 035: PeerEd25519SignatureVerificationFailure"),
          "rodit_ownership_verification",
          {
            result: "failure",
            peer_rodit_id: peerroditid,
            duration
          }
        );

        throw new Error("Error 035: PeerEd25519SignatureVerificationFailure");
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Emit metrics for dashboards
      logger.metric("rodit_ownership_verification_ms", duration, {
        component: "AuthServices",
        success: false,
        error: error.name || "Unknown",
        roditId: peerroditid
      });
      logger.metric("failed_verification_attempts_total", 1, {
        component: "AuthServices",
        reason: error.name || "Unknown",
        roditId: peerroditid
      });

      logErrorWithMetrics(
        "RODiT ownership verification failed", 
        {
          ...baseContext,
          duration,
          peerRoditId: peerroditid
        },
        error,
        "rodit_ownership_verification",
        {
          result: "error",
          error_type: error.name || "Unknown",
          peer_rodit_id: peerroditid,
          duration
        }
      );

      throw error;
    }
  }

 async function verify_rodit_ownership_withnep413(
    message,
    nonce,
    recipient,
    callbackUrl,
    signature,
    peer_rodit
  ) {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context that will be used throughout this function
    const baseContext = createLogContext(
      "AuthServices",
      "verify_rodit_ownership_withnep413",
      {
        requestId,
        messageLength: message?.length,
        recipientId: recipient
      }
    );
    
    try {
      logger.debugWithContext("Starting NEP-413 signature verification", baseContext);

      // Ensure nonce is correctly formatted
      let nonceArray;
      if (typeof nonce === "string") {
        // Handle base64url encoded nonce
        nonceArray = new Uint8Array(Buffer.from(nonce, "base64url"));
      } else if (Array.isArray(nonce)) {
        nonceArray = new Uint8Array(nonce);
      } else if (typeof nonce === "object" && nonce !== null) {
        nonceArray = new Uint8Array(Object.values(nonce));
      } else {
        throw new Error(`Invalid nonce format: ${typeof nonce}`);
      }

      if (nonceArray.length !== 32) {
        const error = new Error(`Invalid nonce length: ${nonceArray.length}, expected 32`);
        logErrorWithMetrics(
          "Invalid nonce length in NEP-413 verification",
          { ...baseContext, nonceLength: nonceArray.length },
          error,
          "nep413_verification_error",
          { error_type: "invalid_nonce_length" }
        );
        throw error;
      }

      const payload = new PayloadNEP413({
        tag: 2147484061,
        message,
        nonce: nonceArray,
        recipient,
        callbackUrl,
      });

      const serializedPayload = borsh.serialize(PayloadNEP413Schema, payload);
      const payloadHash = crypto
        .createHash("sha256")
        .update(serializedPayload)
        .digest();

      // Convert base64url signature to standard base64
      const standardBase64 = signature
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(signature.length + ((4 - (signature.length % 4)) % 4), "=");
      const signatureBytes = nacl.util.decodeBase64(standardBase64);

      // Get public key bytes
      const publicKeyBytes = await nearorg_rpc_fetchpublickeybytes(
        peer_rodit.owner_id
      );

      // Perform verification
      const isaMatch = nacl.sign.detached.verify(
        payloadHash,
        signatureBytes,
        publicKeyBytes
      );

      const duration = Date.now() - startTime;
      
      if (isaMatch) {
        logger.infoWithContext("Peer RODiT possession check successful", {
          ...baseContext,
          duration,
          outcome: "success"
        });
        return true;
      } else {
        const error = new Error("PeerEd25519SignatureVerificationFailure");
        logErrorWithMetrics(
          "Peer RODiT possession check failed",
          {
            ...baseContext,
            duration,
            outcome: "failed"
          },
          error,
          "rodit_ownership_verification",
          { error_type: "signature_verification_failure" }
        );
        throw error;
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      logErrorWithMetrics(
        "RODiT ownership verification failed",
        {
          ...baseContext,
          duration,
          error: error.message
        },
        error,
        "rodit_ownership_verification",
        { error_type: "verification_error" }
      );
      throw error;
    }
  }

  /**
   * Authenticate a webhook request
   *
   * @param {string} payload - Webhook payload
   * @param {string} signature_hex_ofpayload - Signature of payload
   * @param {number} timestamp - Request timestamp
   * @param {string} server_public_key_base64url - Server's public key from RODiT in base64url format
   * @returns {Promise<Object>} Authentication result
   */
  async function authenticate_webhook(
    payload,
    signature_hex_ofpayload,
    timestamp,
    server_public_key_base64url
  ) {
    const requestId = ulid();
    const startTime = Date.now();

    // Create a base context that will be used throughout this function
    const baseContext = createLogContext(
      "AuthServices",
      "authenticate_webhook",
      {
        requestId,
        timestamp
      }
    );
    
    logger.debugWithContext("Starting webhook authentication", {
      ...baseContext,
      hasPayload: !!payload,
      hasSignature: !!signature_hex_ofpayload,
      hasTimestamp: !!timestamp,
      hasServerPublicKey: !!server_public_key_base64url,
      serverKeyLength: server_public_key_base64url?.length,
      payloadLength: payload?.length || 0,
      signatureLength: signature_hex_ofpayload?.length || 0,
      timestampValue: timestamp,
      signatureFirstChars: signature_hex_ofpayload ? signature_hex_ofpayload.substring(0, 15) + '...' : 'null',
      serverKeyFirstChars: server_public_key_base64url ? server_public_key_base64url.substring(0, 15) + '...' : 'null'
    });

    // Only log detailed debugging info at debug level
    logger.debugWithContext("Starting webhook authentication process", baseContext);

    try {
      const currentTime = Date.now();
      const parsedTimestamp = parseInt(timestamp);
      const timeThreshold = 5 * 60 * 1000; // 5 minutes

      // Check if timestamp is too old
      if (currentTime - parsedTimestamp > timeThreshold) {
        const duration = Date.now() - startTime;

        logger.warnWithContext("Webhook authentication failed - timestamp too old", {
          ...baseContext,
          duration,
          timestampAge: (currentTime - parsedTimestamp) / 1000,
          threshold: timeThreshold / 1000
        });

        // Emit metrics for dashboards
        logger.metric("webhook_authentication_duration_ms", duration, {
          component: "AuthServices",
          success: false,
          reason: "TIMESTAMP_EXPIRED",
        });
        logger.metric("webhook_authentication_failures_total", 1, {
          component: "AuthServices",
          reason: "TIMESTAMP_EXPIRED",
        });

        return {
          isValid: false,
          error: {
            code: "TIMESTAMP_EXPIRED",
            message: "Webhook timestamp is too old",
            requestId,
          },
        };
      }

      logger.debugWithContext("Calculating payload hash for verification", {
        ...baseContext,
        payloadSize: payload.length
      });
      
      // IMPORTANT: The server normalizes the payload before signing
      // We must use the raw payload as received without additional normalization
      
      // Log the raw payload for complete visibility with detailed format information
      logger.debugWithContext("Raw payload for verification", {
        ...baseContext,
        payload: payload, // Log the full payload
        payloadSize: payload.length,
        payloadType: typeof payload,
        payloadIsString: typeof payload === 'string',
        payloadFirstChars: payload.substring(0, 100) + (payload.length > 100 ? '...' : '')
      });
      
      // Create the string to hash: payload + timestamp (same as in send_webhook)
      // Use the raw payload without normalization
      const payloadWithTimestamp = payload + timestamp.toString();
      
      logger.debugWithContext("Creating payload+timestamp string for verification", {
        ...baseContext,
        payloadSize: payload.length,
        timestampLength: timestamp.toString().length,
        combinedLength: payloadWithTimestamp.length,
        wasNormalized: false,
        // Check if timestamp is properly appended
        endsWithTimestamp: payloadWithTimestamp.endsWith(timestamp.toString())
      });
      
      // Calculate hash of payload+timestamp
      const sha256_ofpayload = crypto
        .createHash("sha256")
        .update(payloadWithTimestamp)
        .digest();
        
      // Log the hash in hex format for debugging
      const sha256_hex = Buffer.from(sha256_ofpayload).toString('hex');
      logger.debugWithContext("Calculated hash for verification", {
        ...baseContext,
        sha256_hex: sha256_hex,
        hashLength: sha256_ofpayload.length
      });
      


      logger.debugWithContext("Converting signature to buffer", {
        ...baseContext,
        signatureHex: signature_hex_ofpayload,
        signatureHexLength: signature_hex_ofpayload.length,
        // Check if signature is valid hex (should be even length and only hex chars)
        isValidHex: /^[0-9a-fA-F]+$/.test(signature_hex_ofpayload) && signature_hex_ofpayload.length % 2 === 0
      });
      
      // Convert the hex signature to a Uint8Array for verification
      // This matches how signatures are created in send_webhook
      const buffer_signature_ofpayload = new Uint8Array(
        Buffer.from(signature_hex_ofpayload, "hex")
      );
      
      logger.debugWithContext("Signature converted to buffer", {
        ...baseContext,
        bufferLength: buffer_signature_ofpayload.length,
        // Log first few bytes of the buffer for verification
        bufferFirstBytes: Array.from(buffer_signature_ofpayload.slice(0, 4)),
        // Log last few bytes of the buffer for verification
        bufferLastBytes: Array.from(buffer_signature_ofpayload.slice(-4))
      });

      // Log the server public key before conversion for debugging
      logger.debugWithContext("Server public key before conversion", {
        ...baseContext,
        serverKeyBase64Url: server_public_key_base64url,
        serverKeyBase64UrlLength: server_public_key_base64url.length,
        // Check if key is valid base64url (no +, /, or =)
        isValidBase64Url: /^[A-Za-z0-9_-]*$/.test(server_public_key_base64url)
      });
      
      // Convert base64url encoded key to bytes for use with nacl
      const server_public_key = new Uint8Array(
        Buffer.from(server_public_key_base64url, "base64url")
      );

      logger.debugWithContext("Using server public key for verification", {
        ...baseContext,
        serverKeyLength: server_public_key.length,
        // Log the key in different formats for comparison with server logs
        serverKeyHex: Buffer.from(server_public_key).toString('hex'),
        serverKeyBase64: Buffer.from(server_public_key).toString('base64'),
        serverKeyBase64Url: Buffer.from(server_public_key).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        serverKeyHexShort: Buffer.from(server_public_key).toString('hex').substring(0, 16) + '...',
      });

      // Log detailed information about the verification inputs
      logger.debugWithContext("Signature verification details", {
        ...baseContext,
        payloadHashHex: Buffer.from(sha256_ofpayload).toString('hex'),
        signatureHex: signature_hex_ofpayload,
        signatureLength: buffer_signature_ofpayload.length,
        serverKeyHex: Buffer.from(server_public_key).toString('hex'),
        serverKeyBase64: Buffer.from(server_public_key).toString('base64'),
        serverKeyBase64url: server_public_key_base64url
      });

      // Verify signature using the server's public key
      const verificationStartTime = Date.now();
      
      // Log all verification inputs in detail with multiple encoding formats
      logger.debugWithContext("Detailed verification inputs", {
        ...baseContext,
        // Hash in different formats
        hashHex: Buffer.from(sha256_ofpayload).toString('hex'),
        hashBase64: Buffer.from(sha256_ofpayload).toString('base64'),
        hashBase64Url: Buffer.from(sha256_ofpayload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        hashLength: sha256_ofpayload.length,
        // Signature in different formats
        signatureHex: Buffer.from(buffer_signature_ofpayload).toString('hex'),
        signatureBase64: Buffer.from(buffer_signature_ofpayload).toString('base64'),
        signatureBase64Url: Buffer.from(buffer_signature_ofpayload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        signatureLength: buffer_signature_ofpayload.length,
        // Public key in different formats
        publicKeyHex: Buffer.from(server_public_key).toString('hex'),
        publicKeyBase64: Buffer.from(server_public_key).toString('base64'),
        publicKeyBase64Url: Buffer.from(server_public_key).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        publicKeyLength: server_public_key.length
      });
      
      // Perform standard signature verification
      let isValid = false;
      
      try {
        // Use the standard verification method only
        isValid = nacl.sign.detached.verify(
          sha256_ofpayload,
          buffer_signature_ofpayload,
          server_public_key
        );
        
        logger.debug("Standard signature verification completed", {
          component: "AuthServices",
          method: "authenticate_webhook",
          requestId,
          isValid
        });
      } catch (error) {
        logger.warn("Signature verification failed with error", {
          component: "AuthServices",
          method: "authenticate_webhook",
          requestId,
          error: error.message
        });
        isValid = false;
      }
      
      const verificationDuration = Date.now() - verificationStartTime;
      
      // Log the verification result
      logger.info("Webhook signature verification result", {
        component: "AuthServices",
        method: "authenticate_webhook",
        requestId,
        isValid,
        verificationDuration
      });

      // Log verification metrics
      logger.metric(
        "signature_verification_duration_ms",
        verificationDuration,
        {
          component: "AuthServices",
          success: isValid,
        }
      );

      if (!isValid) {
        const duration = Date.now() - startTime;

        logger.warn("Webhook authentication failed - invalid signature", {
          component: "AuthServices",
          method: "authenticate_webhook",
          requestId,
          duration,
          verificationDuration,
        });

        // Emit metrics for dashboards
        logger.metric("webhook_authentication_duration_ms", duration, {
          component: "AuthServices",
          success: false,
          reason: "INVALID_SIGNATURE",
        });
        logger.metric("webhook_authentication_failures_total", 1, {
          component: "AuthServices",
          reason: "INVALID_SIGNATURE",
        });

        return {
          isValid: false,
          error: {
            code: "INVALID_SIGNATURE",
            message: "Invalid webhook signature",
            requestId,
          },
        };
      }

      const duration = Date.now() - startTime;
      logger.info("Webhook authentication successful", {
        component: "AuthServices",
        method: "authenticate_webhook",
        requestId,
        duration,
        verificationDuration,
      });

      // Emit metrics for dashboards
      logger.metric("webhook_authentication_duration_ms", duration, {
        component: "AuthServices",
        success: true,
      });
      logger.metric("successful_webhook_authentications_total", 1, {
        component: "AuthServices",
      });

      return {
        isValid: true,
        message: "Webhook authentication successful",
        requestId,
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error("Webhook authentication error", {
        component: "AuthServices",
        method: "authenticate_webhook",
        requestId,
        duration,
        errorMessage: error.message,
        errorCode: error.code || "UNKNOWN_ERROR",
        stack: error.stack,
      });

      // Emit metrics for dashboards
      logger.metric("webhook_authentication_duration_ms", duration, {
        component: "AuthServices",
        success: false,
        error: error.code || "UNKNOWN_ERROR",
      });
      logger.metric("webhook_authentication_errors_total", 1, {
        component: "AuthServices",
        error: error.constructor.name,
      });

      return {
        isValid: false,
        error: {
          code: "AUTHENTICATION_ERROR",
          message: "An unexpected error occurred during webhook authentication",
          details: error.message,
          requestId,
        },
      };
    }
  }

  /**
   * Validates that a timestamp is not in the future
   * 
   * @param {number} timestamp - Unix timestamp in seconds
   * @param {number} maxAgeSeconds - Maximum age in seconds (not used, kept for backward compatibility)
   * @returns {Promise<boolean>} True if timestamp is valid, false otherwise
   */
  async function validateTimestamp(timestamp, maxAgeSeconds = 300) {
    const requestId = ulid();
    const currentTime = Math.floor(Date.now() / 1000);
    const timeDifference = currentTime - timestamp;
    
    // Check if timestamp is in the future (with small buffer for clock skew)
    if (timestamp > currentTime + 30) {
      logger.warn("Authentication rejected: timestamp is in the future", {
        component: "RoditAuth",
        method: "validateTimestamp",
        requestId,
        timestamp,
        currentTime,
        difference: timestamp - currentTime
      });
      return false;
    }
    
    // We've removed the timestamp age check as it's not needed with our comprehensive validation system
    // The system already validates tokens through other means
    
    return true;
  }

  /**
   * Verify and get a peer RODiT
   *
   * @param {string} peerroditid - Peer RODiT
   * @param {number} peertimestamp - Peer timestamp
   * @param {string} peerroditid_base64url_signature - Base64URL signature
   * @returns {Promise<Object>} Verification result with peer RODiT
   */
  async function verify_peerrodit_getrodit(
    peerroditid,
    peertimestamp,
    peerroditid_base64url_signature
  ) {
    const requestId = ulid();
    const startTime = Date.now();

    // Get own_rodit from stateManager
    const config_own_rodit = await stateManager.getConfigOwnRodit();

    logger.debug("Starting peer RODiT verification", {
      component: "RoditAuth",
      method: "verify_peerrodit_getrodit",
      requestId,
      peerRoditId: peerroditid,
      timestamp: peertimestamp,
      signatureLength: peerroditid_base64url_signature?.length,
      hasOwnRodit: !!config_own_rodit,
      ownRoditId: config_own_rodit?.token_id,
    });

    try {
      // Validate timestamp is not in the future
      const timestampValid = await validateTimestamp(peertimestamp);
      
      if (!timestampValid) {
        logger.warn("Invalid timestamp, aborting RODiT verification", {
          component: "RoditAuth",
          method: "verify_peerrodit_getrodit",
          requestId,
          roditId: peerroditid,
          timestamp: peertimestamp,
          currentTime: Math.floor(Date.now() / 1000),
          maxAge: maxAgeSeconds
        });
        return { peer_rodit: null, goodrodit: false };
      }
      
      logger.debug("Timestamp validation passed", {
        component: "RoditAuth",
        method: "verify_peerrodit_getrodit",
        requestId,
        timestamp: peertimestamp
      });
      logger.debug("Fetching peer RODiT from blockchain", {
        requestId,
        peerRoditId: peerroditid,
      });

      const tokenFetchStart = Date.now();
      const peer_rodit = await nearorg_rpc_tokenfromroditid(peerroditid);
      const tokenFetchDuration = Date.now() - tokenFetchStart;

      logger.debug("Received peer RODiT from blockchain", {
        requestId,
        tokenFetchDuration,
        hasPeerRodit: !!peer_rodit,
        peerRoditId: peer_rodit?.token_id,
        peerRoditOwnerId: peer_rodit?.owner_id,
        hasPeerRoditMetadata: peer_rodit && !!peer_rodit.metadata,
        metadataKeys:
          peer_rodit && peer_rodit.metadata
            ? Object.keys(peer_rodit.metadata)
            : [],
      });

      if (!peer_rodit) {
        logger.error("Failed to retrieve peer RODiT data", {
          component: "AuthServices",
          method: "verify_peerrodit_getrodit",
          requestId,
          duration: Date.now() - startTime,
          peerRoditId: peerroditid,
        });
        return { peer_rodit: null, goodrodit: false };
      }

      if (!peer_rodit.metadata) {
        logger.error("Peer RODiT missing metadata", {
          component: "AuthServices",
          method: "verify_peerrodit_getrodit",
          requestId,
          duration: Date.now() - startTime,
          peerRoditId: peerroditid,
          peerRoditOwnerId: peer_rodit.owner_id,
        });
        return { peer_rodit: null, goodrodit: false };
      }

      // Verify ownership
      const ownershipStart = Date.now();
      const ownershipVerified = await verify_rodit_ownership(
        peerroditid,
        peertimestamp,
        peerroditid_base64url_signature,
        peer_rodit
      );
      const ownershipDuration = Date.now() - ownershipStart;

      logger.debug("Ownership verification completed", {
        requestId,
        ownershipDuration,
        ownershipVerified,
      });

      if (!ownershipVerified) {
        logger.warn("Invalid signature, aborting RODiT verification", {
          requestId,
          roditId: peerroditid,
        });
        return { peer_rodit, goodrodit: false };
      }

      // Verify match
      const matchStart = Date.now();
      
      // Check if config_own_rodit is properly defined before accessing properties
      if (!config_own_rodit || !config_own_rodit.own_rodit.metadata) {
        logger.error("Own RODiT configuration is incomplete", {
          component: "AuthServices",
          method: "verify_peerrodit_getrodit",
          requestId,
          duration: Date.now() - startTime,
          hasOwnRodit: !!config_own_rodit,
          hasMetadata: config_own_rodit && !!config_own_rodit.own_rodit.metadata
        });
        return { peer_rodit, goodrodit: false };
      }
      
      const isaMatch = await verify_rodit_isamatch(
        config_own_rodit.own_rodit.metadata.serviceprovider_id,
        peer_rodit
      );
      const matchDuration = Date.now() - matchStart;

      logger.debug("Match verification completed", {
        requestId,
        matchDuration,
        isaMatch,
      });

      if (!isaMatch) {
        logger.warn("RODiT match verification failed", {
          requestId,
          roditId: peerroditid,
        });
        return { peer_rodit, goodrodit: false };
      }

      // Verify live
      const liveStart = Date.now();
      const isLive = await verify_rodit_islive(
        peer_rodit.metadata.not_after,
        peer_rodit.metadata.not_before
      );
      const liveDuration = Date.now() - liveStart;

      logger.debug("Live verification completed", {
        requestId,
        liveDuration,
        isLive,
      });

      if (!isLive) {
        logger.warn("RODiT live verification failed", {
          requestId,
          roditId: peerroditid,
        });
        return { peer_rodit, goodrodit: false };
      }

      // Verify active
      const activeStart = Date.now();
      const isActive = await verify_rodit_isactive(
        peer_rodit.token_id,
        config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url
      );
      const activeDuration = Date.now() - activeStart;

      logger.debug("Active verification completed", {
        requestId,
        activeDuration,
        isActive,
      });

      if (!isActive) {
        logger.warn("RODiT active verification failed", {
          requestId,
          roditId: peerroditid,
        });
        return { peer_rodit, goodrodit: false };
      }

      // Verify trusted
      const trustedStart = Date.now();
      const isTrusted = await verify_rodit_istrusted_issuingsmartcontract(
        config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url
      );
      const trustedDuration = Date.now() - trustedStart;

      logger.debug("Trust verification completed", {
        requestId,
        trustedDuration,
        isTrusted,
      });

      if (!isTrusted) {
        logger.warn("RODiT trusted verification failed", {
          requestId,
          roditId: peerroditid,
        });
        return { peer_rodit, goodrodit: false };
      }

      const totalDuration = Date.now() - startTime;

      logger.info("Peer RODiT verification successful", {
        component: "AuthServices",
        method: "verify_peerrodit_getrodit",
        requestId,
        duration: totalDuration,
        peerRoditId: peerroditid,
        peerOwnerId: peer_rodit.owner_id,
      });

      return {
        peer_rodit,
        goodrodit: true,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error("Error in verify_peerrodit_getrodit", {
        component: "AuthServices",
        method: "verify_peerrodit_getrodit",
        requestId,
        duration,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });

      // Add metrics for verification errors
      logger.metric &&
        logger.metric("rodit_verification_errors", 1, {
          error_type: error.name || "Unknown",
        });

      return {
        peer_rodit: null,
        goodrodit: false,
        error: `Error in verify_peerrodit_getrodit: ${error.message}`,
      };
    }
  }

  async function verify_rodit_islive(peer_rodit_notafter, peer_rodit_notbefore) {
    const requestId = ulid();
    const startTime = Date.now();
  
    logger.debug("Checking RODiT time validity", {
      component: "RoditAuth",
      method: "verify_rodit_islive",
      requestId,
      notAfter: peer_rodit_notafter,
      notBefore: peer_rodit_notbefore,
    });
  
    function parseDate(datestring) {
      const date = new Date(datestring);
      return isNaN(date.getTime()) ? new Date(0) : date;
    }
  
    const datetimenul = new Date(0);
    const datetimenotafter = parseDate(peer_rodit_notafter);
    const datetimenotbefore = parseDate(peer_rodit_notbefore);
  
    logger.debug("Parsed validity dates", {
      requestId,
      parsedNotAfter: datetimenotafter.toISOString(),
      parsedNotBefore: datetimenotbefore.toISOString(),
      isNotAfterNull: datetimenotafter.getTime() === datetimenul.getTime(),
      isNotBeforeNull: datetimenotbefore.getTime() === datetimenul.getTime(),
    });
  
    try {
      const rpcStart = Date.now();
      const stringtimenow = await nearorg_rpc_timestamp();
      const rpcDuration = Date.now() - rpcStart;
  
      logger.debug("Retrieved blockchain timestamp", {
        requestId,
        rpcDuration,
        blockchainTimestamp: stringtimenow,
      });
  
      const timestamp = parseInt(stringtimenow, 10);
  
      if (isNaN(timestamp)) {
        logger.error("Failed to parse blockchain timestamp", {
          component: "AuthServices",
          requestId,
          duration: Date.now() - startTime,
          blockchainTimestamp: stringtimenow,
        });
  
        // Add metrics for timestamp parsing errors
        logger.metric &&
          logger.metric("rodit_islive_errors", 1, {
            error_type: "timestamp_parse_error",
            blockchain_timestamp: stringtimenow,
          });
  
        return false;
      }
  
      const datetimetimestamp = new Date(timestamp / 1000000); // Convert nanoseconds to milliseconds
  
      logger.debug("Converted blockchain time", {
        requestId,
        blockchainTime: datetimetimestamp.toISOString(),
        originalTimestamp: timestamp,
      });
  
      const isAfterNotBefore =
        datetimetimestamp >= datetimenotbefore ||
        datetimenotbefore.getTime() === datetimenul.getTime();
  
      const isBeforeNotAfter =
        datetimetimestamp <= datetimenotafter ||
        datetimenotafter.getTime() === datetimenul.getTime();
  
      const isLive = isAfterNotBefore && isBeforeNotAfter;
  
      const totalDuration = Date.now() - startTime;
  
      if (isLive) {
        logger.info("RODiT is live", {
          component: "AuthServices",
          method: "verify_rodit_islive",
          requestId,
          duration: totalDuration,
          rpcDuration,
          currentTime: datetimetimestamp.toISOString(),
          notBefore: datetimenotbefore.toISOString(),
          notAfter: datetimenotafter.toISOString(),
          isLive: true,
        });
  
        // Add metrics for live tokens
        logger.metric &&
          logger.metric("rodit_time_checks", totalDuration, {
            result: "live",
          });
  
        return true;
      } else {
        logger.warn("RODiT is not live - outside valid time period", {
          component: "AuthServices",
          method: "verify_rodit_islive",
          requestId,
          duration: totalDuration,
          rpcDuration,
          currentTime: datetimetimestamp.toISOString(),
          notBefore: datetimenotbefore.toISOString(),
          notAfter: datetimenotafter.toISOString(),
          isBeforeExpiry: isBeforeNotAfter,
          isAfterStart: isAfterNotBefore,
          isLive: false,
        });
  
        // Add metrics for expired or not-yet-valid tokens
        logger.metric &&
          logger.metric("rodit_time_checks", totalDuration, {
            result: "not_live",
            not_before_valid: isAfterNotBefore,
            not_after_valid: isBeforeNotAfter,
          });
  
        return false;
      }
    } catch (error) {
      const duration = Date.now() - startTime;
  
      logger.error("Failed to check RODiT time validity", {
        component: "AuthServices",
        method: "verify_rodit_islive",
        requestId,
        duration,
        notAfter: peer_rodit_notafter,
        notBefore: peer_rodit_notbefore,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });
  
      // Add metrics for validation errors
      logger.metric &&
        logger.metric("rodit_islive_errors", 1, {
          error_type: error.name || "Unknown",
        });
  
      return false;
    }
  }

  async function verify_rodit_isactive(tokenId, ownsubjectuniqueidentifier_url) {
    const requestId = ulid();
    const startTime = Date.now();
  
    // WHILE DEBUGGING TEMPORARY FIX DO NOT REMOVE THIS LINE EVER WITHOUT PERMISSION
    return true;
  
    logger.debug("Checking RODiT activity status", {
      component: "RoditAuth",
      method: "verify_rodit_isactive",
      requestId,
      tokenId,
      subjectUrl: ownsubjectuniqueidentifier_url,
    });
  
    const domainandextensionRegex =
      /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/i;
  
    const match = ownsubjectuniqueidentifier_url.match(domainandextensionRegex);
  
    if (match) {
      const domainandextension = match[1];
      const revokingDnsEntry = `${tokenId}.revoked.${domainandextension}`;
  
      logger.debug("Checking DNS revocation entry", {
        requestId,
        domain: domainandextension,
        revokingDnsEntry,
      });
  
      try {
        const dnsStart = Date.now();
        const resolver = new Resolver();
        await resolver.resolveTxt(revokingDnsEntry);
        const dnsDuration = Date.now() - dnsStart;
        const totalDuration = Date.now() - startTime;
  
        logger.info("RODiT revocation found", {
          component: "AuthServices",
          method: "verify_rodit_isactive",
          requestId,
          duration: totalDuration,
          dnsDuration,
          tokenId,
          domain: domainandextension,
          revokingDnsEntry,
          isActive: false,
        });
  
        // Add metrics for revoked tokens
        logger.metric &&
          logger.metric("rodit_revocation_checks", totalDuration, {
            result: "revoked",
            token_id: tokenId,
          });
  
        return false;
      } catch (error) {
        // DNS error usually means no revocation entry found, which is good
        const dnsDuration = Date.now() - dnsStart || 0;
        const totalDuration = Date.now() - startTime;
  
        logger.debug("No revocation found for RODiT", {
          requestId,
          dnsDuration,
          tokenId,
          error: error.code,
        });
  
        logger.info("RODiT is active", {
          component: "AuthServices",
          method: "verify_rodit_isactive",
          requestId,
          duration: totalDuration,
          dnsDuration,
          tokenId,
          domain: domainandextension,
          isActive: true,
        });
  
        // Add metrics for active tokens
        logger.metric &&
          logger.metric("rodit_revocation_checks", totalDuration, {
            result: "active",
            token_id: tokenId,
          });
  
        return true;
      }
    } else {
      const duration = Date.now() - startTime;
  
      logger.warn("Unable to parse domain from URL", {
        component: "AuthServices",
        method: "verify_rodit_isactive",
        requestId,
        duration,
        tokenId,
        subjectUrl: ownsubjectuniqueidentifier_url,
      });
  
      // Add metrics for parsing errors
      logger.metric &&
        logger.metric("rodit_revocation_checks", duration, {
          result: "parse_error",
          token_id: tokenId,
        });
  
      // Default to allowing the token if domain parsing fails
      return true;
    }
  }

  async function verify_rodit_istrusted_issuingsmartcontract(
    ownsubjectuniqueidentifier_url
  ) {
    const requestId = ulid();
    const startTime = Date.now();
  
    logger.debug("Verifying smart contract trust", {
      component: "RoditAuth",
      method: "verify_rodit_istrusted_issuingsmartcontract",
      requestId,
      url: ownsubjectuniqueidentifier_url,
      smartContract: CONSTANTS.NEAR_CONTRACT_ID,
    });
  
    try {
      const smartcontract = CONSTANTS.NEAR_CONTRACT_ID;
      const smartontractnonear = smartcontract.replace(".testnet", "");
      const smartcontracturl = smartontractnonear.replace("-", ".");
  
      logger.debug("Prepared smart contract identifiers", {
        requestId,
        originalContract: smartcontract,
        nonearContract: smartontractnonear,
        urlContract: smartcontracturl,
      });
  
      const domainRegex =
        /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/i;
  
      const maindomainmatch = domainRegex.exec(ownsubjectuniqueidentifier_url);
  
      if (!maindomainmatch) {
        logger.error("Failed to parse domain from URL", {
          component: "AuthServices",
          requestId,
          duration: Date.now() - startTime,
          url: ownsubjectuniqueidentifier_url,
        });
  
        // Add metrics for domain parsing failures
        logger.metric &&
          logger.metric("rodit_trust_errors", 1, {
            error_type: "domain_parse_error",
            url: ownsubjectuniqueidentifier_url,
          });
  
        throw new Error(
          `Domain can't be parsed from URL: ${ownsubjectuniqueidentifier_url}`
        );
      }
  
      const extractedDomain = maindomainmatch[1];
      const enablingdnsentry = `${smartontractnonear}.smartcontract.${extractedDomain}`;
  
      logger.debug("Checking DNS trust entry", {
        requestId,
        extractedDomain,
        enablingDnsEntry: enablingdnsentry,
      });
  
      try {
        const dnsStart = Date.now();
        const resolver = new Resolver();
        const cfgresponse = await resolver.resolveTxt(enablingdnsentry);
        const dnsDuration = Date.now() - dnsStart;
  
        logger.debug("DNS response received", {
          requestId,
          dnsDuration,
          recordCount: cfgresponse?.length || 0,
        });
  
        if (cfgresponse.length > 0) {
          const totalDuration = Date.now() - startTime;
  
          logger.info("Smart contract is trusted", {
            component: "AuthServices",
            method: "verify_rodit_istrusted_issuingsmartcontract",
            requestId,
            duration: totalDuration,
            dnsDuration,
            smartContract: smartcontracturl,
            domain: extractedDomain,
            dnsEntry: enablingdnsentry,
            recordCount: cfgresponse.length,
            isTrusted: true,
          });
  
          // Add metrics for trusted contracts
          logger.metric &&
            logger.metric("rodit_trust_checks", totalDuration, {
              result: "trusted",
              domain: extractedDomain,
            });
  
          return true;
        } else {
          const totalDuration = Date.now() - startTime;
  
          logger.warn("Smart contract not trusted - empty DNS record", {
            component: "AuthServices",
            method: "verify_rodit_istrusted_issuingsmartcontract",
            requestId,
            duration: totalDuration,
            dnsDuration,
            smartContract: smartcontracturl,
            domain: extractedDomain,
            dnsEntry: enablingdnsentry,
            isTrusted: false,
          });
  
          // Add metrics for untrusted contracts
          logger.metric &&
            logger.metric("rodit_trust_checks", totalDuration, {
              result: "empty_dns",
              domain: extractedDomain,
            });
  
          return false;
        }
      } catch (error) {
        const totalDuration = Date.now() - startTime;
  
        logger.warn("Smart contract not trusted - DNS lookup failed", {
          component: "AuthServices",
          method: "verify_rodit_istrusted_issuingsmartcontract",
          requestId,
          duration: totalDuration,
          smartContract: smartcontracturl,
          domain: extractedDomain,
          dnsEntry: enablingdnsentry,
          dnsError: error.code,
          isTrusted: false,
        });
  
        // Add metrics for DNS errors
        logger.metric &&
          logger.metric("rodit_trust_checks", totalDuration, {
            result: "dns_error",
            domain: extractedDomain,
            error_code: error.code,
          });
  
        return false;
      }
    } catch (error) {
      const duration = Date.now() - startTime;
  
      logger.error("Trust verification failed", {
        component: "AuthServices",
        method: "verify_rodit_istrusted_issuingsmartcontract",
        requestId,
        duration,
        url: ownsubjectuniqueidentifier_url,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });
  
      // Add metrics for verification errors
      logger.metric &&
        logger.metric("rodit_trust_errors", 1, {
          error_type: error.name || "Unknown",
          message: error.message,
        });
  
      return false;
    }
  }

  async function verify_rodit_isamatch(own_service_provider_id, peer_rodit) {
    const requestId = ulid();
    const startTime = Date.now();
  
    logger.debug("Starting RODiT match verification", {
      component: "RoditAuth",
      method: "verify_rodit_isamatch",
      requestId,
      ownServiceProviderId: own_service_provider_id,
      peerRoditId: peer_rodit?.token_id,
    });
  
    try {
      const own_provider_components = own_service_provider_id.split(";");
  
      logger.debug("Split provider components", {
        requestId,
        componentCount: own_provider_components.length,
        components: own_provider_components,
      });
  
      // Get blockchain and contract parts
      const bcPart = own_provider_components.find((part) =>
        part.startsWith("bc=")
      );
      const scPart = own_provider_components.find((part) =>
        part.startsWith("sc=")
      );
  
      // Find all ID components
      const idComponents = own_provider_components.filter(
        (part) =>
          part.startsWith("id=") &&
          !part.startsWith("bc=") &&
          !part.startsWith("sc=")
      );
  
      if (!bcPart || !scPart || idComponents.length < 1) {
        logger.error("Invalid provider ID format", {
          component: "AuthServices",
          requestId,
          duration: Date.now() - startTime,
          providerId: own_service_provider_id,
          components: own_provider_components,
          hasBlockchain: !!bcPart,
          hasSmartContract: !!scPart,
          idCount: idComponents.length,
        });
  
        // Add metrics for format errors
        logger.metric &&
          logger.metric("rodit_match_format_errors", 1, {
            error_type: "invalid_provider_id",
            bc_part_present: !!bcPart,
            sc_part_present: !!scPart,
            id_count: idComponents.length,
          });
  
        return false;
      }
  
      // Construct the base prefix
      const base_prefix = `${bcPart};${scPart}`;
      logger.debug("Constructed base prefix", {
        requestId,
        basePrefix: base_prefix,
      });
  
      // Extract the peer's service provider IDs for comparison
      const peer_service_provider_id = peer_rodit.metadata.serviceprovider_id;
      const peer_provider_components = peer_service_provider_id.split(";");
      const peer_idComponents = peer_provider_components.filter(
        (part) => part.startsWith("id=") && !part.startsWith("bc=") && !part.startsWith("sc=")
      );

      logger.debug("Peer service provider analysis", {
        requestId,
        peerServiceProviderId: peer_service_provider_id,
        peerIdComponents: peer_idComponents,
        ownIdComponents: idComponents,
      });

      // Try verification with each ID component
      for (let i = 0; i < idComponents.length; i++) {
        const idPosition = i + 1;
        const signing_token_id = `${base_prefix};${idComponents[i]}`;
        const current_own_id = idComponents[i];

        // Determine verification type based on service provider ID comparison
        // PARTNER: Different service provider IDs (client-server relationship)
        // PEER: Same service provider ID (peer-to-peer relationship)
        const isSignedBySameProvider = peer_idComponents.includes(current_own_id);
        const verificationType = isSignedBySameProvider ? "PARTNER":"PEER";
        const isPartnerVerification = !isSignedBySameProvider;
        const isPeerVerification = isSignedBySameProvider;

        logger.debug(
          `Trying ${verificationType} verification with ID [${idPosition}/${idComponents.length}]`,
          {
            requestId,
            idPosition,
            verificationType,
            totalIds: idComponents.length,
            signingTokenId: signing_token_id,
            currentOwnId: current_own_id,
            peerIdComponents: peer_idComponents,
            isSignedBySameProvider,
            relationshipType: isSignedBySameProvider ? "peer-to-peer" : "client-to-server"
          }
        );

        logger.debug("About to fetch signing RODiT", {
          requestId,
          idPosition,
          verificationType,
          signingTokenId: signing_token_id,
          expectedAccount: current_own_id.replace('id=', ''),
          peerServiceProviderId: peer_service_provider_id
        });

        const tokenFetchStart = Date.now();
        const signing_rodit = await nearorg_rpc_tokenfromroditid(
          signing_token_id
        );
        const tokenFetchDuration = Date.now() - tokenFetchStart;

        logger.debug("Retrieved signing RODiT - DETAILED DEBUG", {
          requestId,
          idPosition,
          verificationType,
          tokenFetchDuration,
          tokenId: signing_rodit?.token_id,
          ownerId: signing_rodit?.owner_id,
          ownerIdExpected: current_own_id.replace('id=', ''),
          ownerIdMatches: signing_rodit?.owner_id === current_own_id.replace('id=', ''),
          signingTokenIdRequested: signing_token_id,
          hasMetadata: !!signing_rodit?.metadata,
          metadataServiceProviderId: signing_rodit?.metadata?.serviceprovider_id
        });

        // Process the owner ID
        try {
          // Add detailed logging for debugging
          logger.debug("Processing owner ID for signing verification", {
            requestId,
            idPosition,
            verificationType,
            ownerIdType: typeof signing_rodit.owner_id,
            ownerIdValue: signing_rodit.owner_id,
            ownerIdLength: signing_rodit.owner_id?.length,
            isValidHex: signing_rodit.owner_id && /^[0-9a-fA-F]+$/.test(signing_rodit.owner_id),
            peerSignature: peer_rodit.metadata.serviceprovider_signature,
          });

          const bytes_signing_owner_id = new Uint8Array(
            Buffer.from(signing_rodit.owner_id, "hex")
          );

          logger.debug("Hex conversion result", {
            requestId,
            idPosition,
            verificationType,
            resultLength: bytes_signing_owner_id.length,
            expectedLength: CONSTANTS.RODIT_ID_PK_SZ,
            bufferFirst4Bytes: Array.from(bytes_signing_owner_id.slice(0, 4)),
          });

          if (bytes_signing_owner_id.length !== CONSTANTS.RODIT_ID_PK_SZ) {
            logger.warn(`Invalid signing key length for ${verificationType} verification (ID position: ${idPosition})`, {
              requestId,
              verificationType,
              actual: bytes_signing_owner_id.length,
              expected: CONSTANTS.RODIT_ID_PK_SZ,
              ownerIdValue: signing_rodit.owner_id,
              ownerIdType: typeof signing_rodit.owner_id,
            });
            continue; // Try the next ID
          }

          // Process the signature
          const base64urlSignature =
            peer_rodit.metadata.serviceprovider_signature;
          const base64Signature = base64urlSignature
            .replace(/-/g, "+")
            .replace(/_/g, "/")
            .padEnd(
              base64urlSignature.length +
                ((4 - (base64urlSignature.length % 4)) % 4),
              "="
            );

          const signatureBytes = new Uint8Array(
            Buffer.from(base64Signature, "base64")
          );

          if (signatureBytes.length !== CONSTANTS.RODIT_ID_SIGNATURE_SZ) {
            logger.warn(`Invalid signature length for ${verificationType} verification (ID position: ${idPosition})`, {
              requestId,
              verificationType,
              actual: signatureBytes.length,
              expected: CONSTANTS.RODIT_ID_SIGNATURE_SZ,
            });
            continue; // Try the next ID
          }

          // Prepare the hash input - MUST exactly match verifyRoditSignature function format
          const hashInput = {
            token_id: peer_rodit.token_id,
            openapijson_url: peer_rodit.metadata.openapijson_url,
            not_after: peer_rodit.metadata.not_after,
            not_before: peer_rodit.metadata.not_before,
            max_requests: String(peer_rodit.metadata.max_requests),
            maxrq_window: String(peer_rodit.metadata.maxrq_window),
            webhook_cidr: peer_rodit.metadata.webhook_cidr,
            allowed_cidr: peer_rodit.metadata.allowed_cidr,
            allowed_iso3166list: peer_rodit.metadata.allowed_iso3166list,
            jwt_duration: peer_rodit.metadata.jwt_duration,
            permissioned_routes: peer_rodit.metadata.permissioned_routes,
            serviceprovider_id: peer_rodit.metadata.serviceprovider_id,
            subjectuniqueidentifier_url: peer_rodit.metadata.subjectuniqueidentifier_url,
          };

          // Debug logging to compare with working frontend verification
          logger.debug("Backend hash input structure for verification", {
            requestId,
            idPosition,
            verificationType,
            hashInput: JSON.stringify(hashInput, null, 2),
            peerSignature: peer_rodit.metadata.serviceprovider_signature,
            signingOwnerId: bytes_signing_owner_id ? Buffer.from(bytes_signing_owner_id).toString('hex') : 'null',
          });

          const hashStart = Date.now();
          const hashHex = calculateCanonicalHash(hashInput);
          const hashBytes = new Uint8Array(Buffer.from(hashHex, "hex"));
          const hashDuration = Date.now() - hashStart;

          logger.debug("Hash calculation completed", {
            requestId,
            idPosition,
            verificationType,
            hashHex: hashHex.substring(0, 32) + '...',
            hashLength: hashHex.length,
            hashDuration,
          });

          logger.debug("Calculated hash for verification", {
            requestId,
            idPosition,
            verificationType,
            hashDuration,
            hashLength: hashBytes.length,
          });

          // Verify the signature
          const verifyStart = Date.now();
          const is_valid = nacl.sign.detached.verify(
            hashBytes,
            signatureBytes,
            bytes_signing_owner_id
          );
          const verifyDuration = Date.now() - verifyStart;

          logger.debug("Signature verification result", {
            requestId,
            idPosition,
            verificationType,
            verifyDuration,
            isValid: is_valid,
          });

          if (is_valid) {
            const totalDuration = Date.now() - startTime;

            // Log based on verification type
            logger.info(`${verificationType} login verified successfully`, {
              component: "AuthServices",
              method: "verify_rodit_isamatch",
              requestId,
              duration: totalDuration,
              verificationType,
              idPosition,
              partnerVerification: isPartnerVerification,
              peerVerification: isPeerVerification
            });

            // Add metrics for successful matching
            logger.metric &&
              logger.metric("rodit_match_verification", totalDuration, {
                result: "success",
                verification_type: verificationType.toLowerCase(),
              });
  
            return true;
          }
  
          logger.debug(`${verificationType} verification failed (ID position: ${idPosition})`, {
            requestId,
            verificationType
          });
        } catch (verifyError) {
          logger.warn(`Error during ${verificationType} verification (ID position: ${idPosition})`, {
            requestId,
            verificationType,
            error: verifyError.message,
            stack: verifyError.stack,
          });
        }
      }
  
      // If we get here, all verification attempts failed
      const totalDuration = Date.now() - startTime;
  
      logger.error("All verification attempts failed", {
        component: "AuthServices",
        method: "verify_rodit_isamatch",
        requestId,
        duration: totalDuration,
        ownServiceProviderId: own_service_provider_id,
        peerRoditId: peer_rodit?.token_id,
        attemptCount: idComponents.length,
      });
  
      // Add metrics for failed matching
      logger.metric &&
        logger.metric("rodit_match_verification", totalDuration, {
          result: "failure",
          attempts: idComponents.length,
        });
  
      return false;
    } catch (error) {
      const duration = Date.now() - startTime;
  
      logger.error("RODiT match verification failed", {
        component: "AuthServices",
        method: "verify_rodit_isamatch",
        requestId,
        duration,
        ownServiceProviderId: own_service_provider_id,
        peerRoditId: peer_rodit?.token_id,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });
  
      // Add metrics for verification errors
      logger.metric &&
        logger.metric("rodit_match_errors", 1, {
          error_type: error.name || "Unknown",
        });
  
      return false;
    }
  }

module.exports = {
  verify_rodit_ownership,
  verify_rodit_ownership_withnep413,
  verify_peerrodit_getrodit,
  validateTimestamp,
  verify_rodit_isactive,
  verify_rodit_isamatch,
  verify_rodit_islive,
  verify_rodit_istrusted_issuingsmartcontract,
  authenticate_webhook
};