/**
 * Service for JWT token operations
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require("ulid");
const config = require('../../services/configsdk');
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const nacl = require("tweetnacl");
const crypto = require("crypto");
const {
  dateStringToUnixTime,
  unixTimeToDateString
} = require("../../services/utils");
const { sessionManager } = require('./sessionmanager');

// Log which SessionManager instance is being used
logger.infoWithContext("TokenService using SessionManager instance", {
  component: "TokenService",
  event: "sessionManager_import",
  sessionManagerInstanceId: sessionManager._instanceId,
  timestamp: new Date().toISOString()
});
const stateManager = require('../blockchain/statemanager');
const {  
  nearorg_rpc_tokenfromroditid, 
  nearorg_rpc_tokensfromaccountid, 
  nearorg_rpc_fetchpublickeybytes,
} = require("../blockchain/blockchainservice");

// Dynamic import for ESM 'jose' in CommonJS context
let _josePromise;
async function getJose() {
  if (!_josePromise) {
    _josePromise = import("jose");
  }
  return _josePromise;
}

// Destructure SignJWT from jose
const { SignJWT } = require('jose');

  /**
   * Converts a base64url string to a JWK public key
   *
   * @param {string} base64url_public_key - Base64url encoded public key
   * @returns {Promise<Object>} JWK public key object
   */
  async function base64url2jwk_public_key(base64url_public_key) {
    const startTime = Date.now();
    const requestId = ulid();
    
    // Create a base context that will be used throughout this function
    const baseContext = createLogContext(
      "Transformer",
      "base64url2jwk_public_key",
      { requestId }
    );
    
    logger.debugWithContext("Converting base64url to JWK public key", baseContext);

    try {
      const jwk_public_key = {
        kty: "OKP",
        crv: "Ed25519",
        x: base64url_public_key,
        use: "sig",
      };

      logger.debug("JWK public key structure created", {
        component: "Transformer",
        method: "base64url2jwk_public_key",
        requestId,
        jwk: {
          kty: jwk_public_key.kty,
          crv: jwk_public_key.crv,
          use: jwk_public_key.use,
          xLength: jwk_public_key.x.length,
        },
      });

      const { importJWK } = await getJose();
      const session_jwk_public_key = await importJWK(jwk_public_key, "EdDSA");

      const duration = Date.now() - startTime;
      
      logger.debugWithContext("JWK public key import successful", {
        ...baseContext,
        duration
      });

      // Emit metrics for dashboards
      logger.metric("jwk_import_duration_ms", duration, {
        component: "Transformer",
        success: true
      });

      return session_jwk_public_key;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Use logErrorWithMetrics for standardized error logging and metrics
      logErrorWithMetrics({
        error,
        context: {
          ...baseContext,
          duration
        },
        metrics: [
          {
            name: "jwk_import_duration_ms",
            value: duration,
            tags: { success: false, error: error.constructor.name }
          },
          {
            name: "jwk_import_errors_total",
            value: 1,
            tags: { errorType: error.constructor.name }
          }
        ]
      });

      throw error;
    }
  }

  /**
   * Verifies a JWT token
   *
   * @param {string} token - JWT token to verify
   * @param {Object} jwk_public_key - JWK public key for verification
   * @param {number} timestamp - Current timestamp
   * @param {string} requestId - Request ID for tracking
   * @returns {Promise<Object>} Verification result with payload
   */
  async function verify_jwt_token(token, jwk_public_key, timestamp, requestId) {
    const startTime = Date.now();

    logger.debug("Starting token verification", {
      component: "TokenVerifier",
      method: "verify_jwt_token",
      requestId,
      hasTimestamp: !!timestamp,
    });

    try {
      const { jwtVerify } = await getJose();
      const result = await jwtVerify(token, jwk_public_key, {
        algorithms: ["EdDSA"],
      });

      const duration = Date.now() - startTime;

      // Log session information if available
      const sessionInfo = {
        sessionId: result.payload.session_id || "none",
        sessionStatus: result.payload.session_status || "unknown",
        sessionCreatedAt: result.payload.session_iat
          ? new Date(result.payload.session_iat * 1000).toISOString()
          : "unknown",
        sessionExpiresAt: result.payload.session_exp
          ? new Date(result.payload.session_exp * 1000).toISOString()
          : "unknown",
      };

      logger.debug("Token verified successfully", {
        component: "TokenVerifier",
        method: "verify_jwt_token",
        requestId,
        duration,
        subject: result.payload.sub,
        tokenExpiration: new Date(result.payload.exp * 1000).toISOString(),
        timeLeft: Math.floor(result.payload.exp - Date.now() / 1000),
        ...sessionInfo,
      });

      // Emit metrics for dashboards
      logger.metric("token_verification_duration_ms", duration, {
        component: "TokenVerifier",
        success: true,
        session_status: result.payload.session_status || "unknown",
      });
      logger.metric("token_verifications_total", 1, {
        component: "TokenVerifier",
        success: true,
        algorithm: "EdDSA",
        session_status: result.payload.session_status || "unknown",
      });

      return result;
    } catch (jwtError) {
      const duration = Date.now() - startTime;

      if (jwtError.code === "ERR_JWT_EXPIRED") {
        logger.warn("Token expired, attempting renewal", {
          component: "TokenVerifier",
          method: "verify_jwt_token",
          requestId,
          duration,
          errorCode: jwtError.code,
          errorMessage: jwtError.message,
        });

        // Emit metrics for dashboards
        logger.metric("token_verification_duration_ms", duration, {
          component: "TokenVerifier",
          success: false,
          error: "TOKEN_EXPIRED",
        });
        logger.metric("token_verifications_total", 1, {
          component: "TokenVerifier",
          success: false,
          error: "TOKEN_EXPIRED",
        });
        logger.metric("expired_tokens_total", 1, {
          component: "TokenVerifier",
        });

        try {
          const config_own_rodit = await stateManager.getConfigOwnRodit();
          const { decodeJwt } = await getJose();
          const unverifiedpayload = decodeJwt(token);

          // Log session information from expired token
          const sessionInfo = {
            sessionId: unverifiedpayload.session_id || "none",
            sessionStatus: unverifiedpayload.session_status || "unknown",
            sessionCreatedAt: unverifiedpayload.session_iat
              ? new Date(unverifiedpayload.session_iat * 1000).toISOString()
              : "unknown",
          };

          logger.debug("Validating expired token for renewal", {
            component: "TokenVerifier",
            method: "verify_jwt_token",
            requestId,
            subject: unverifiedpayload.sub,
            tokenId: unverifiedpayload.jti || "unknown",
            ...sessionInfo,
          });

          const renewalStartTime = Date.now();
          const { isValid, notAfter } =
            await thorough_validate_jwt_token_be(
              unverifiedpayload,
              requestId
            );

          if (isValid) {
            logger.info("Generating new token for expired but valid token", {
              component: "TokenVerifier",
              method: "verify_jwt_token",
              requestId,
              subject: unverifiedpayload.sub,
              notAfter: notAfter,
              sessionId: unverifiedpayload.session_id || "none",
            });

            // Use full verification for expired tokens
            const newToken = await generate_jwt_token_fromtoken(
              unverifiedpayload,
              config_own_rodit.own_rodit.metadata.jwt_duration,
              notAfter,
              timestamp,
              "full" // Expired tokens require full verification
            );

            const renewalDuration = Date.now() - renewalStartTime;
            logger.debug("Successfully generated renewal token", {
              component: "TokenVerifier",
              method: "verify_jwt_token",
              requestId,
              renewalDuration,
              totalDuration: Date.now() - startTime,
              sessionStatus: "renewed_full_verification",
            });

            // Emit metrics for dashboards
            logger.metric("token_renewal_duration_ms", renewalDuration, {
              component: "TokenVerifier",
              success: true,
              reason: "EXPIRED",
              session_status: "renewed_full_verification",
            });
            logger.metric("token_renewals_total", 1, {
              component: "TokenVerifier",
              reason: "EXPIRED",
              session_status: "renewed_full_verification",
            });

            return {
              payload: unverifiedpayload,
              protectedHeader: null,
              newToken,
            };
          }

          const renewalDuration = Date.now() - renewalStartTime;
          logger.error("Token renewal failed - invalid token", {
            component: "TokenVerifier",
            method: "verify_jwt_token",
            requestId,
            renewalDuration,
            totalDuration: Date.now() - startTime,
            tokenId: unverifiedpayload.jti || "unknown",
            sessionId: unverifiedpayload.session_id || "none",
          });

          // Emit metrics for dashboards
          logger.metric("token_renewal_duration_ms", renewalDuration, {
            component: "TokenVerifier",
            success: false,
            error: "VALIDATION_FAILED",
          });
          logger.metric("token_renewal_failures_total", 1, {
            component: "TokenVerifier",
            reason: "VALIDATION_FAILED",
          });
        } catch (renewalError) {
          logger.error("Error during token renewal process", {
            component: "TokenVerifier",
            method: "verify_jwt_token",
            requestId,
            duration: Date.now() - startTime,
            errorMessage: renewalError.message,
            errorCode: renewalError.code || "UNKNOWN_ERROR",
            stack: renewalError.stack,
          });

          // Emit metrics for dashboards
          logger.metric("token_renewal_errors_total", 1, {
            component: "TokenVerifier",
            error: renewalError.code || "UNKNOWN_ERROR",
          });
        }
      } else {
        // Handle other JWT errors
        logger.error("JWT verification error", {
          component: "TokenVerifier",
          method: "verify_jwt_token",
          requestId,
          duration,
          errorCode: jwtError.code || "UNKNOWN_ERROR",
          errorMessage: jwtError.message,
          stack: jwtError.stack,
        });

        // Emit metrics for dashboards
        logger.metric("token_verification_duration_ms", duration, {
          component: "TokenVerifier",
          success: false,
          error: jwtError.code || "UNKNOWN_ERROR",
        });
        logger.metric("token_verifications_total", 1, {
          component: "TokenVerifier",
          success: false,
          error: jwtError.code || "UNKNOWN_ERROR",
        });
      }

      throw jwtError;
    }
  }

  /**
   * Generate a new JWT token
   *
   * @param {Object} peer_rodit - Peer RODiT token object
   * @param {number} peer_timestamp - Peer timestamp
   * @param {Object} own_rodit - Own RODiT token object
   * @param {Uint8Array} own_rodit_bytes_private_key - Private key bytes
   * @param {string} session_status - Session status
   * @returns {Promise<string>} Generated JWT token
   */
  async function generate_jwt_token(
    peer_rodit,
    peer_timestamp,
    own_rodit,
    own_rodit_bytes_private_key,
    session_status = "new"
  ) {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context that will be used throughout this function
    const baseContext = createLogContext(
      "JwtAuth",
      "generate_jwt_token",
      {
        requestId,
        peerRoditId: peer_rodit?.token_id,
        peerTimestamp: peer_timestamp,
        ownRoditId: own_rodit?.token_id,
        sessionStatus: session_status
      }
    );
    
    // DEVELOPMENT ENVIRONMENT ONLY - Add detailed private key debugging
    logger.debugWithContext("PRIVATE KEY DEBUG - Function Entry", {
      ...baseContext,
      keyType: typeof own_rodit_bytes_private_key,
      isUint8Array: own_rodit_bytes_private_key instanceof Uint8Array,
      isBuffer: Buffer.isBuffer(own_rodit_bytes_private_key),
      keyLength: own_rodit_bytes_private_key ? own_rodit_bytes_private_key.length : 0,
      keyConstructor: own_rodit_bytes_private_key ? own_rodit_bytes_private_key.constructor.name : 'undefined',
      keyIsNull: own_rodit_bytes_private_key === null,
      keyIsNotDefined: own_rodit_bytes_private_key === undefined,
      keyToString: own_rodit_bytes_private_key ? String(own_rodit_bytes_private_key).substring(0, 100) : 'N/A',
      keyHasOwnProperty: own_rodit_bytes_private_key ? Object.getOwnPropertyNames(own_rodit_bytes_private_key).join(',') : 'N/A',
      keyPrototype: own_rodit_bytes_private_key ? Object.getPrototypeOf(own_rodit_bytes_private_key)?.constructor?.name : 'N/A',
      // DEV ONLY - Show actual key bytes for debugging
      keyFirstBytes: own_rodit_bytes_private_key && own_rodit_bytes_private_key.length > 0 ? 
        Array.from(own_rodit_bytes_private_key.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ') : 'N/A',
      keySource: 'tokenservice.generate_jwt_token.entry'
    });
    
    logger.debugWithContext("Starting JWT token generation", baseContext);

    try {
      const now = peer_timestamp;

      const notafterStart = Date.now();
      const notafter = await dateStringToUnixTime(
        peer_rodit.metadata.not_after
      );
      const notafterDuration = Date.now() - notafterStart;

      // Get token duration from peer RODiT
      const peerTokenDuration = parseInt(peer_rodit.metadata.jwt_duration, 10);
      const tokenDuration = Math.floor(peerTokenDuration);

      // Get session duration from own RODiT (typically longer)
      const ownSessionDuration = parseInt(own_rodit.metadata.jwt_duration, 10);
      const sessionDuration = Math.floor(ownSessionDuration);

      // Calculate expirations
      let tokenExpiration = now + tokenDuration;
      let sessionExpiration = now + sessionDuration;

      logger.debugWithContext("Calculated token parameters", {
        ...baseContext,
        now,
        notafter,
        tokenDuration,
        sessionDuration,
        notafterDuration
      });

      // Validate token expiration doesn't exceed RODiT validity
      if (tokenExpiration > notafter) {
        tokenExpiration = notafter;
        logger.debugWithContext("Token expiration capped by RODiT validity", {
          ...baseContext,
          tokenExpiration,
          notafter
        });
      }

      // Validate session expiration doesn't exceed RODiT validity
      if (sessionExpiration > notafter) {
        sessionExpiration = notafter;
        logger.debugWithContext("Session expiration capped by RODiT validity", {
          ...baseContext,
          sessionExpiration,
          notafter
        });
      }

      const notbeforeStart = Date.now();
      const notbefore = await dateStringToUnixTime(
        own_rodit.metadata.not_before
      );
      const notbeforeDuration = Date.now() - notbeforeStart;

      logger.debugWithContext("Retrieved not-before time", {
        ...baseContext,
        notbefore,
        notbeforeDuration
      });

      const encodeStart = Date.now();
      const timeString = await unixTimeToDateString(peer_timestamp);
      const roditidandtimestamp = new TextEncoder().encode(
        own_rodit.token_id + timeString
      );
      const encodeDuration = Date.now() - encodeStart;

      logger.debugWithContext("Encoded RODiT and timestamp", {
        ...baseContext,
        encodeDuration,
        roditIdLength: own_rodit.token_id.length,
        timestampLength: now.toString().length,
        totalLength: roditidandtimestamp.length
      });

      const signatureStart = Date.now();
      
      // DEVELOPMENT ENVIRONMENT ONLY - Add detailed private key debugging before signing
      logger.debugWithContext("PRIVATE KEY DEBUG - Before Signing", {
        ...baseContext,
        keyType: typeof own_rodit_bytes_private_key,
        isUint8Array: own_rodit_bytes_private_key instanceof Uint8Array,
        isBuffer: Buffer.isBuffer(own_rodit_bytes_private_key),
        keyLength: own_rodit_bytes_private_key ? own_rodit_bytes_private_key.length : 0,
        keyConstructor: own_rodit_bytes_private_key ? own_rodit_bytes_private_key.constructor.name : 'undefined',
        keyIsNull: own_rodit_bytes_private_key === null,
        keyIsNotDefined: own_rodit_bytes_private_key === undefined,
        keySource: 'tokenservice.generate_jwt_token.before_signing',
        // DEV ONLY - Show actual key bytes for debugging
        keyFirstBytes: own_rodit_bytes_private_key && own_rodit_bytes_private_key.length > 0 ? 
          Array.from(own_rodit_bytes_private_key.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ') : 'N/A',
        dataToSign: roditidandtimestamp.toString('hex').substring(0, 50) + '...'
      });
      
      // Check if the private key is a Uint8Array, which is required for nacl.sign.detached
      let privateKeyToUse = own_rodit_bytes_private_key;
      
      // Add diagnostic logging to help identify the issue
      if (!(own_rodit_bytes_private_key instanceof Uint8Array)) {
        // Capture detailed information about the key
        const keyInfo = {
          ...baseContext,
          type: typeof own_rodit_bytes_private_key,
          isNull: own_rodit_bytes_private_key === null,
          isUndefined: own_rodit_bytes_private_key === undefined,
          isBuffer: Buffer.isBuffer(own_rodit_bytes_private_key),
          keyLength: own_rodit_bytes_private_key ? own_rodit_bytes_private_key.length : 0,
          keyConstructor: own_rodit_bytes_private_key ? own_rodit_bytes_private_key.constructor.name : 'undefined',
          // DEV ONLY - Show actual key representation for debugging
          keyStringified: own_rodit_bytes_private_key ? 
            JSON.stringify(own_rodit_bytes_private_key).substring(0, 100) + '...' : 'N/A',
          keySource: 'tokenservice.generate_jwt_token'
        };
        
        // Log the detailed information
        logger.debugWithContext("Private key is not a Uint8Array - Detailed Analysis", keyInfo);
        
        // If it's a Buffer, we can convert it to a Uint8Array
        if (Buffer.isBuffer(own_rodit_bytes_private_key)) {
          logger.infoWithContext("Converting Buffer to Uint8Array", baseContext);
          privateKeyToUse = new Uint8Array(own_rodit_bytes_private_key);
          
          // Verify the conversion was successful
          logger.debugWithContext("Buffer conversion result", {
            ...baseContext,
            convertedIsUint8Array: privateKeyToUse instanceof Uint8Array,
            convertedLength: privateKeyToUse.length,
            originalLength: own_rodit_bytes_private_key.length,
            // DEV ONLY - Show first few bytes to verify integrity
            convertedFirstBytes: Array.from(privateKeyToUse.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '),
            originalFirstBytes: Array.from(own_rodit_bytes_private_key.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ')
          });
        } else if (typeof own_rodit_bytes_private_key === 'object' && own_rodit_bytes_private_key !== null) {
          // Try to recover from a JSON-serialized Uint8Array or similar object
          logger.warnWithContext("Attempting to recover private key from non-standard format", {
            ...baseContext,
            recoveryAttempt: true
          });
          
          try {
            // If it's an array-like object, try to convert it to Uint8Array
            if (Array.isArray(own_rodit_bytes_private_key) || 
                (own_rodit_bytes_private_key.length !== undefined && typeof own_rodit_bytes_private_key.length === 'number')) {
              privateKeyToUse = new Uint8Array(
                Array.isArray(own_rodit_bytes_private_key) ? 
                  own_rodit_bytes_private_key : 
                  Array.from(own_rodit_bytes_private_key)
              );
              
              logger.infoWithContext("Successfully recovered private key from array-like object", {
                ...baseContext,
                recoveredKeyLength: privateKeyToUse.length,
                recoveredIsUint8Array: privateKeyToUse instanceof Uint8Array,
                // DEV ONLY - Show first few bytes
                recoveredFirstBytes: Array.from(privateKeyToUse.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ')
              });
            } else {
              throw new Error("Cannot recover key - not an array-like object");
            }
          } catch (recoveryError) {
            logErrorWithMetrics({
              error: new Error(`Private key recovery failed: ${recoveryError.message}`),
              context: {
                ...keyInfo,
                recoveryError: recoveryError.message
              },
              metrics: [
                {
                  name: "private_key_recovery_failures",
                  value: 1,
                  tags: { keyType: typeof own_rodit_bytes_private_key }
                }
              ]
            });
            throw new Error("Private key must be a Uint8Array or Buffer for nacl.sign.detached");
          }
        } else {
          logErrorWithMetrics({
            error: new Error("Private key must be a Uint8Array or Buffer for nacl.sign.detached"),
            context: keyInfo,
            metrics: [
              {
                name: "private_key_format_errors_total",
                value: 1,
                tags: { keyType: typeof own_rodit_bytes_private_key }
              }
            ]
          });
          throw new Error("Private key must be a Uint8Array or Buffer for nacl.sign.detached");
        }
      }
      
      const own_rodit_bytes_signature = nacl.sign.detached(
        roditidandtimestamp,
        privateKeyToUse
      );
      const signatureDuration = Date.now() - signatureStart;

      logger.debugWithContext("Created signature", {
        ...baseContext,
        signatureDuration,
        signatureLength: own_rodit_bytes_signature.length
      });

      const base64Start = Date.now();
      const own_roditid_base64url_signature = Buffer.from(
        own_rodit_bytes_signature
      ).toString("base64url");
      const base64Duration = Date.now() - base64Start;

      logger.debugWithContext("Converted signature to base64url", {
        ...baseContext,
        base64Duration,
        base64Length: own_roditid_base64url_signature.length
      });

      const keyStart = Date.now();
      const own_rodit_keyobject_private_key = crypto.createPrivateKey({
        key: Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          own_rodit_bytes_private_key,
        ]),
        format: "der",
        type: "pkcs8",
      });
      const keyDuration = Date.now() - keyStart;

      logger.debugWithContext("Created private key object", {
        ...baseContext,
        keyDuration
      });

      // Create and register session in SessionManager
      const sessionData = {
        roditId: peer_rodit.token_id,
        ownerId: peer_rodit.owner_id,
        createdAt: now,
        expiresAt: sessionExpiration,
        metadata: {
          serviceProviderId: peer_rodit.metadata.serviceprovider_id,
          ownRoditId: own_rodit.token_id,
          notAfter: peer_rodit.metadata.not_after,
          status: session_status,
        },
      };

      let session_id = null; // Initialize to null, will be set by createSession
      const sessionCreateStart = Date.now();
      
      // Always attempt to create a session - SessionManager should handle all cases
      try {
        if (!sessionManager) {
          logger.errorWithContext("Session manager is undefined - this should never happen", {
            ...baseContext,
            roditId: peer_rodit.token_id
          });
          throw new Error("SessionManager is required for token generation");
        }
        
        if (typeof sessionManager.createSession !== 'function') {
          logger.errorWithContext("Session manager createSession method is not available", {
            ...baseContext,
            roditId: peer_rodit.token_id,
            sessionManagerType: typeof sessionManager,
            hasCreateSession: sessionManager ? 'createSession' in sessionManager : false
          });
          throw new Error("SessionManager.createSession method is required");
        }

        // Session manager is available, proceed with session creation
        const session = await sessionManager.createSession(sessionData);
        const sessionCreateDuration = Date.now() - sessionCreateStart;

        // Use the actual session ID returned by createSession
        session_id = session?.id;

        if (!session_id) {
          throw new Error("SessionManager.createSession returned invalid session");
        }

        logger.infoWithContext("Session created in session manager", {
          ...baseContext,
          sessionId: session?.id,
          roditId: peer_rodit.token_id,
          sessionStatus: session?.status,
          sessionExpiresAt: session?.expiresAt,
          sessionManagerInstanceId: sessionManager._instanceId,
          sessionCreateDuration
        });
        
      } catch (sessionError) {
        logger.errorWithContext(
          "Failed to create session - cannot generate JWT token without valid session",
          {
            ...baseContext,
            error: sessionError.message,
            roditId: peer_rodit.token_id,
            sessionManagerInstanceId: sessionManager?._instanceId
          }
        );
        throw new Error(`Session creation failed: ${sessionError.message}`);
      }

      const jwtId = "jti" + ulid();
      
      // Validate session_id before embedding in JWT token
      if (!session_id || typeof session_id !== 'string' || session_id.trim() === '') {
        logger.errorWithContext("Invalid session ID for JWT token generation", {
          ...baseContext,
          sessionIdForJWT: session_id,
          sessionIdType: typeof session_id,
          jwtId,
          roditId: peer_rodit.token_id,
          sessionManagerInstanceId: sessionManager._instanceId
        });
        throw new Error(`Invalid session ID for JWT token: ${session_id}`);
      }
      
      // Log the session ID that will be embedded in the JWT token
      logger.infoWithContext("Embedding session ID in JWT token", {
        ...baseContext,
        sessionIdForJWT: session_id,
        sessionIdLength: session_id.length,
        jwtId,
        roditId: peer_rodit.token_id,
        sessionManagerInstanceId: sessionManager._instanceId
      });
      
      const jwtSignStart = Date.now();
      const { SignJWT } = await getJose();
      const token = await new SignJWT({
        iss: peer_rodit.metadata.subjectuniqueidentifier_url,
        sub:
          peer_rodit.metadata.serviceprovider_id +
          ";sub=" +
          peer_rodit.token_id,
        aud: own_rodit.owner_id,
        exp: tokenExpiration,
        nbf: notbefore,
        iat: now,
        jti: jwtId,
        // Add session information
        session_id: session_id,
        session_iat: now,
        session_exp: sessionExpiration,
        session_status: session_status,
        rodit_id: own_rodit.token_id,
        rodit_owner: own_rodit.owner_id,
        rodit_idsignature: own_roditid_base64url_signature,
        rodit_maxrequests: peer_rodit.metadata.max_requests,
        rodit_maxrqwindow: peer_rodit.metadata.maxrq_window,
        rodit_permissionedroutes: peer_rodit.metadata.permissioned_routes,
        rodit_webhookcidr: peer_rodit.metadata.webhook_cidr,
        rodit_allowedcidr: peer_rodit.metadata.allowed_cidr,
        rodit_allowediso3166list: peer_rodit.metadata.allowed_iso3166list,
        rodit_webhookurl: peer_rodit.metadata.webhook_url,
        config_iso639: null,
        config_iso3166: null,
        config_iso15924: null,
        config_timeoptions: null,
      })
        .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
        .sign(own_rodit_keyobject_private_key);
      const jwtSignDuration = Date.now() - jwtSignStart;

      const totalDuration = Date.now() - startTime;

      logger.infoWithContext("JWT token generation successful", {
        ...baseContext,
        duration: totalDuration,
        notafterDuration,
        notbeforeDuration,
        encodeDuration,
        signatureDuration,
        base64Duration,
        keyDuration,
        jwtSignDuration,
        peerRoditId: peer_rodit.token_id,
        ownRoditId: own_rodit.token_id,
        jwtId,
        sessionId: session_id,
        sessionStatus: session_status,
        tokenValidFor: tokenExpiration - now,
        sessionValidFor: sessionExpiration - now
      });

      // Add metrics for successful token generation
      logger.metric("jwt_token_generation", totalDuration, {
        result: "success",
        peer_rodit_id: peer_rodit.token_id,
        valid_seconds: tokenExpiration - now,
        session_status: session_status,
      });

      return token;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      logErrorWithMetrics({
        error,
        context: {
          ...baseContext,
          duration,
          peerRoditId: peer_rodit?.token_id,
          ownRoditId: own_rodit?.token_id
        },
        metrics: [
          {
            name: "jwt_token_generation_errors",
            value: 1,
            tags: {
              error_type: error.name || "Unknown",
              peer_rodit_id: peer_rodit?.token_id || "unknown"
            }
          }
        ]
      });

      throw error;
    }
  }

  /**
   * Generate a new JWT token from an existing token
   *
   * @param {Object} token - Token payload
   * @param {number} duration - New token duration in seconds
   * @param {string} notafter - Not-after date string
   * @param {number} timestamp - Current timestamp
   * @param {string} verification_level - Verification level used
   * @returns {Promise<string>} New JWT token
   */
  async function generate_jwt_token_fromtoken(
    token,
    duration,
    notafter,
    timestamp,
    verification_level = "light"
  ) {
    const requestId = ulid();
    const startTime = Date.now();

    // Set session status based on verification level
    const session_status =
      verification_level === "full"
        ? "renewed_full_verification"
        : "renewed_light_verification";

    logger.debug("Starting token renewal process", {
      component: "JwtAuth",
      method: "generate_jwt_token_fromtoken",
      requestId,
      tokenJti: token?.jti,
      duration,
      notAfter: notafter,
      timestamp,
      verificationLevel: verification_level,
      sessionStatus: session_status,
    });

    try {
      const now = Math.floor(Date.now() / 1000);

      // Get token and session information from existing token
      const existingSessionId = token.session_id;

      // Check if session exists and is active in session manager
      const sessionCheckStart = Date.now();
      let isSessionValid = true;

      if (existingSessionId) {
        try {
          isSessionValid = stateManager.isSessionActive(existingSessionId);

          logger.debug("Checked session status", {
            component: "JwtAuth",
            method: "generate_jwt_token_fromtoken",
            requestId,
            sessionId: existingSessionId,
            isSessionValid,
            checkDuration: Date.now() - sessionCheckStart,
          });

          if (!isSessionValid) {
            logger.warn("Session inactive or closed - token renewal rejected", {
              component: "JwtAuth",
              method: "generate_jwt_token_fromtoken",
              requestId,
              sessionId: existingSessionId,
              tokenJti: token.jti,
            });

            throw new Error("Session inactive or closed");
          }
        } catch (sessionError) {
          logger.error("Session check failed", {
            component: "JwtAuth",
            method: "generate_jwt_token_fromtoken",
            requestId,
            sessionId: existingSessionId,
            error: sessionError.message,
          });
          // Continue with token renewal even if session check fails
          // This provides graceful degradation if session service is unavailable
        }
      }

      // Calculate new token expiration time (using the provided duration)
      const slashedDuration = Math.floor(duration);
      const tokenexpiration = slashedDuration + now;
      const notafterunixtime = await dateStringToUnixTime(notafter);

      logger.debug("Calculated expiration times", {
        requestId,
        now,
        tokenExpiration: tokenexpiration,
        notAfterUnixTime: notafterunixtime,
        willExpireBefore: tokenexpiration <= notafterunixtime,
      });

      // Ensure token doesn't expire after RODiT validity
      if (tokenexpiration > notafterunixtime) {
        logger.warn("Token renewal failed - RODiT expired", {
          component: "JwtAuth",
          requestId,
          duration: Date.now() - startTime,
          notAfterUnixTime: notafterunixtime,
          tokenExpiration: tokenexpiration,
          difference: tokenexpiration - notafterunixtime,
        });

        throw new Error("RODiT has expired");
      }

      const configStart = Date.now();
      const config_own_rodit = await stateManager.getConfigOwnRodit();
      const configDuration = Date.now() - configStart;

      logger.debug("Retrieved configuration", {
        requestId,
        configDuration,
        hasConfig: !!config_own_rodit,
      });

      const keyCreationStart = Date.now();
      const own_rodit_keyobject_private_key = crypto.createPrivateKey({
        key: Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          config_own_rodit.own_rodit_bytes_private_key,
        ]),
        format: "der",
        type: "pkcs8",
      });
      const keyCreationDuration = Date.now() - keyCreationStart;

      logger.debug("Created private key object", {
        requestId,
        keyCreationDuration,
      });

      // Keep existing session ID and creation time
      const session_id = existingSessionId;
      const session_iat = token.session_iat;

      // Keep the original session expiration time consistent across renewals
      const session_exp = token.session_exp;

      // Update session information if needed
      if (session_id) {
        const sessionUpdateStart = Date.now();
        try {
          stateManager.updateSession(session_id, {
            lastAccessedAt: now,
            status: "active",
            metadata: {
              ...stateManager.getSession(session_id)?.metadata,
              lastRenewalType: verification_level,
              lastRenewalTime: now,
            },
          });

          logger.debug("Session updated in session manager", {
            component: "JwtAuth",
            method: "generate_jwt_token_fromtoken",
            requestId,
            sessionId: session_id,
            updateDuration: Date.now() - sessionUpdateStart,
          });
        } catch (sessionError) {
          logger.warn("Failed to update session", {
            component: "JwtAuth",
            method: "generate_jwt_token_fromtoken",
            requestId,
            sessionId: session_id,
            error: sessionError.message,
          });
          // Continue even if session update fails
        }
      }

      const jwtCreateStart = Date.now();
      const jwtId = "jti" + ulid();
      const newtoken = await new SignJWT({
        iss: token.iss,
        sub: token.sub,
        aud: token.aud,
        exp: tokenexpiration,
        nbf: token.nbf,
        iat: now,
        jti: jwtId,
        // Include consistent session information
        session_id: session_id,
        session_iat: session_iat,
        session_exp: session_exp,
        session_status: session_status,
        rodit_id: token.rodit_id,
        rodit_owner: token.rodit_owner,
        rodit_allowediso3166list: token.rodit_allowediso3166list,
        rodit_idsignature: token.rodit_idsignature,
        rodit_maxrequests: token.rodit_maxrequests,
        rodit_maxrqwindow: token.rodit_maxrqwindow,
        rodit_permissionedroutes: token.rodit_permissionedroutes,
        rodit_webhookcidr: token.rodit_webhookcidr,
        rodit_allowedcidr: token.rodit_allowedcidr,
        rodit_webhookurl: token.rodit_webhookurl,
        config_iso639: null,
        config_iso3166: null,
        config_iso15924: null,
        config_timeoptions: null,
      })
        .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
        .sign(own_rodit_keyobject_private_key);
      const jwtCreateDuration = Date.now() - jwtCreateStart;

      const totalDuration = Date.now() - startTime;

      logger.info("JWT token renewal successful", {
        component: "JwtAuth",
        method: "generate_jwt_token_fromtoken",
        requestId,
        duration: totalDuration,
        configDuration,
        keyCreationDuration,
        jwtCreateDuration,
        tokenJti: token.jti,
        newTokenJti: jwtId,
        newTokenExpiration: tokenexpiration,
        sessionId: session_id,
        sessionExpiration: new Date(session_exp * 1000).toISOString(),
        sessionStatus: session_status,
        verificationLevel: verification_level,
        validFor: tokenexpiration - now,
      });

      // Add metrics for successful token renewals
      logger.metric("jwt_token_renewals", totalDuration, {
        result: "success",
        valid_seconds: tokenexpiration - now,
        verification_level: verification_level,
        session_status: session_status,
      });

      return newtoken;
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error("Failed to generate new JWT token", {
        component: "JwtAuth",
        method: "generate_jwt_token_fromtoken",
        requestId,
        duration,
        tokenJti: token.jti,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });
      // Add metrics for token generation errors
      logger.metric("jwt_token_renewal_errors", 1, {
        error_type: error.name || "Unknown",
        token_jti: token.jti || "unknown",
      });

      throw error;
    }
  }

  /**
   * Generate a session termination token for logout
   * 
   * @param {Object} decodedToken - The decoded JWT token from the user's request
   * @param {number} duration - Token duration in seconds (typically short for termination tokens)
   * @returns {Promise<string>} Generated session termination token
   */
  async function generate_session_termination_token(decodedToken, duration = 60) {
    const requestId = ulid();
    const startTime = Date.now();
    
    logger.debug("Starting session termination token generation", {
      component: "JwtAuth",
      method: "generate_session_termination_token",
      requestId,
      tokenJti: decodedToken?.jti,
      sessionId: decodedToken?.session_id,
      duration
    });
    
    try {
      // Get configuration from state manager
      const config_own_rodit = await stateManager.getConfigOwnRodit();
      
      if (!config_own_rodit || !config_own_rodit.own_rodit) {
        throw new Error("Missing own RODiT configuration");
      }
      
      const now = Math.floor(Date.now() / 1000);
      const exp = now + duration;
      
      // Create payload with session_status="closed"
      const payload = {
        ...decodedToken,
        iat: now,
        exp: exp,
        session_status: "closed",
        jti: ulid() // Generate a new unique ID for this token
      };
      
      // Create a proper private key object from the raw bytes
      const own_rodit_keyobject_private_key = crypto.createPrivateKey({
        key: Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          config_own_rodit.own_rodit_bytes_private_key,
        ]),
        format: "der",
        type: "pkcs8",
      });
      
      // Sign the token with the proper key object
      const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
        .sign(own_rodit_keyobject_private_key);
      
      logger.info("Generated session termination token", {
        component: "JwtAuth",
        method: "generate_session_termination_token",
        requestId,
        duration: Date.now() - startTime,
        tokenJti: payload.jti,
        expiration: new Date(exp * 1000).toISOString()
      });
      
      return token;
    } catch (error) {
      logger.error("Failed to generate session termination token", {
        component: "JwtAuth",
        method: "generate_session_termination_token",
        requestId,
        duration: Date.now() - startTime,
        error: error.message,
        stack: error.stack
      });
      
      throw error;
    }
  }

  /**
   * Validate a JWT token
   *
   * @param {Object} token - Token payload
   * @param {Object} rodit - RODiT token object
   * @returns {Promise<Object>} Validation result with payload
   */
  async function validate_jwt_token_be(token, rodit) {
    const requestId = ulid();
    const startTime = Date.now();
    let isExpired = false;

    logger.debug("Starting JWT token validation", {
      component: "JwtAuth",
      method: "validate_jwt_token_be",
      requestId,
      tokenLength: token?.length,
      hasOwnRodit: !!rodit,
      ownRoditId: rodit?.token_id,
    });

    try {
      // Decode the token without verification to get the payload
      const { decodeJwt } = await getJose();
      const unverifiedpayload = decodeJwt(token);

      logger.debug("Decoded JWT payload", {
        requestId,
        iss: unverifiedpayload?.iss,
        jti: unverifiedpayload?.jti,
        exp: unverifiedpayload?.exp,
        roditId: unverifiedpayload?.rodit_id,
        aud: unverifiedpayload?.aud,
      });

      logger.debug("Fetching service provider RODiT from blockchain", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        roditId: unverifiedpayload.rodit_id,
        tokenAud: unverifiedpayload.aud,
        tokenIss: unverifiedpayload.iss
      });
      
      const sp_rodit = await nearorg_rpc_tokenfromroditid(
        unverifiedpayload.rodit_id
      );
      
      logger.debug("Service provider RODiT lookup result", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        roditId: unverifiedpayload.rodit_id,
        hasSpRodit: !!sp_rodit,
        spRoditTokenId: sp_rodit?.token_id,
        spRoditOwnerId: sp_rodit?.owner_id,
        spRoditMetadata: !!sp_rodit?.metadata,
        spRoditKeys: sp_rodit ? Object.keys(sp_rodit) : [],
        spRoditIsEmpty: sp_rodit && Object.keys(sp_rodit).length === 0,
        nearContractId: config.get("NEAR_CONTRACT_ID"),
        nearRpcUrl: config.get("NEAR_RPC_URL")
      });
      
      // Additional diagnostic logging for troubleshooting
      if (sp_rodit && Object.keys(sp_rodit).length === 0) {
        logger.warn("RODiT lookup returned empty object - RODiT likely does not exist on blockchain", {
          component: "JwtAuth",
          method: "validate_jwt_token_be",
          requestId,
          roditId: unverifiedpayload.rodit_id,
          nearContractId: config.get("NEAR_CONTRACT_ID"),
          nearRpcUrl: config.get("NEAR_RPC_URL"),
          suggestion: "Verify RODiT ID exists on the specified NEAR contract"
        });
      }
      
      if (!sp_rodit || !sp_rodit.token_id) {
        const errorDetails = {
          component: "JwtAuth",
          method: "validate_jwt_token_be",
          requestId,
          roditId: unverifiedpayload.rodit_id,
          duration: Date.now() - startTime,
          hasSpRodit: !!sp_rodit,
          spRoditKeys: sp_rodit ? Object.keys(sp_rodit) : [],
          spRoditOwnerId: sp_rodit?.owner_id || null,
          spRoditTokenId: sp_rodit?.token_id || null,
          nearContractId: config.get("NEAR_CONTRACT_ID"),
          nearRpcUrl: config.get("NEAR_RPC_URL"),
          tokenPayload: {
            aud: unverifiedpayload.aud,
            iss: unverifiedpayload.iss,
            sub: unverifiedpayload.sub,
            rodit_id: unverifiedpayload.rodit_id
          },
          diagnosisInfo: {
            roditExists: !!sp_rodit,
            hasTokenId: !!(sp_rodit && sp_rodit.token_id),
            hasOwnerId: !!(sp_rodit && sp_rodit.owner_id),
            isEmpty: sp_rodit && Object.keys(sp_rodit).length === 0,
            possibleCause: !sp_rodit ? "RODiT not found on blockchain" : 
                          !sp_rodit.token_id ? "RODiT exists but missing token_id field" : 
                          "Unknown validation failure"
          }
        };

        logger.warn("Token validation failed - Invalid or missing service provider RODiT", errorDetails);
        
        // Enhanced error message with diagnostic information
        const diagnosticMessage = `Error 008: Invalid or missing service provider RODiT (ID: ${unverifiedpayload.rodit_id}). ` +
          `Diagnosis: ${errorDetails.diagnosisInfo.possibleCause}. ` +
          `Contract: ${config.get("NEAR_CONTRACT_ID")}, Network: ${config.get("NEAR_RPC_URL")}`;
        
        throw new Error(diagnosticMessage);
      }
      
      logger.debug("Retrieved service provider RODiT", {
        requestId,
        spRoditId: sp_rodit?.token_id,
        spOwnerId: sp_rodit?.owner_id,
      });

      const publicKeyBytes = await nearorg_rpc_fetchpublickeybytes(
        sp_rodit.owner_id
      );
  
      const serviceprovider_base64_public_key =
        Buffer.from(publicKeyBytes).toString("base64url");
  
      logger.debug("Converted public key to base64url", {
        requestId,
        keyLength: serviceprovider_base64_public_key?.length,
      });
  
      const sp_public_key = await base64url2jwk_public_key(
        serviceprovider_base64_public_key
      );
  
      logger.debug("Converted to JWK public key", { requestId });
  
      let payload;
      // Define jwtVerifyStartTime outside the try block so it's accessible in both try and catch
      const jwtVerifyStartTime = Date.now();
      
      try {
        // Try to verify the token signature
        const { jwtVerify } = await getJose();
        const verifyResult = await jwtVerify(token, sp_public_key, {
          algorithms: ["EdDSA"],
        });
        payload = verifyResult.payload;
        
        logger.debug("JWT signature verified", {
          requestId,
          jwtVerifyDuration: Date.now() - jwtVerifyStartTime,
        });
      } catch (jwtError) {
        // Check if this is an expiration error
        if (jwtError.name === "JWTExpired") {
          logger.info("JWT token expired, will attempt renewal", {
            component: "JwtAuth",
            method: "validate_jwt_token_be",
            requestId,
            errorName: jwtError.name,
            errorMessage: jwtError.message
          });
          isExpired = true;
          payload = unverifiedpayload; // Use the unverified payload for renewal
        } else {
          // For other JWT errors, rethrow
          throw jwtError;
        }
      }
  
      // Only log JWT verification success if we didn't hit an error
      if (!isExpired) {
        logger.debug("JWT signature verified", {
          requestId,
          jwtVerifyDuration: Date.now() - jwtVerifyStartTime,
        });
      }
    
      const { verify_peerrodit_getrodit } = require("./authentication");
      
      const verifyStartTime = Date.now();
      let { peer_rodit, goodrodit } = await verify_peerrodit_getrodit(
        unverifiedpayload.rodit_id,
        unverifiedpayload.iat,
        unverifiedpayload.rodit_idsignature
      );

      logger.debug("Verified peer RODiT", {
        requestId,
        verifyPeerDuration: Date.now() - verifyStartTime,
        goodRodit: goodrodit,
      });
  
      if (!goodrodit) {
        logger.warn("Token validation failed - Invalid peer RODiT", {
          component: "JwtAuth",
          method: "validate_jwt_token_be",
          requestId,
          roditId: payload.rodit_id,
          duration: Date.now() - startTime,
        });
        
        throw new Error("Error 009: Invalid peer RODiT verification");
      }
  
      // Token expiration check - only perform if we haven't already detected expiration
      const now = Math.floor(Date.now() / 1000);
      if (!isExpired && payload.exp <= now) {
        logger.warn("Token validation failed - Token expired", {
          component: "JwtAuth",
          requestId,
          exp: payload.exp,
          now,
          difference: now - payload.exp,
        });
        
        isExpired = true;
      }
  
      // Token not-before check
      if (payload.nbf > now) {
        logger.warn("Token validation failed - Token not yet valid", {
          component: "JwtAuth",
          requestId,
          nbf: payload.nbf,
          now,
          difference: payload.nbf - now,
        });
  
        throw new Error("Error 006: Token is not yet valid");
      }
  
      // Function to normalize URL by removing port
      const normalizeUrlWithoutPort = (url) => {
        if (!url) return '';
        try {
          // Use URL constructor to parse the URL
          const parsedUrl = new URL(url);
          // Remove the port
          parsedUrl.port = '';
          // Return the normalized URL as a string
          return parsedUrl.toString();
        } catch (e) {
          // If URL parsing fails, return the original URL
          return url;
        }
      };
      
      // Normalize both URLs for comparison
      const normalizedTokenIssuer = normalizeUrlWithoutPort(payload.iss);
      const normalizedExpectedIssuer = normalizeUrlWithoutPort(rodit.metadata.subjectuniqueidentifier_url);
      
      // Issuer check with enhanced logging
      logger.debug("Detailed issuer validation information", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        tokenIssuer: payload.iss,
        expectedIssuer: rodit.metadata.subjectuniqueidentifier_url,
        normalizedTokenIssuer,
        normalizedExpectedIssuer,
        roditId: rodit.token_id,
        roditOwnerId: rodit.owner_id,
        hasMetadata: !!rodit.metadata,
        metadataKeys: rodit.metadata ? Object.keys(rodit.metadata) : [],
        payloadKeys: Object.keys(payload),
        rawIssuerMatch: payload.iss === rodit.metadata.subjectuniqueidentifier_url,
        normalizedIssuerMatch: normalizedTokenIssuer === normalizedExpectedIssuer
      });
      
      // Compare normalized URLs instead of raw URLs
      if (normalizedTokenIssuer !== normalizedExpectedIssuer) {
        logger.warn("Token validation failed - Invalid issuer", {
          component: "JwtAuth",
          method: "validate_jwt_token_be",
          requestId,
          tokenIssuer: payload.iss,
          expectedIssuer: rodit.metadata.subjectuniqueidentifier_url,
          normalizedTokenIssuer,
          normalizedExpectedIssuer,
          roditId: rodit.token_id,
          // Check for common URL variations that might cause mismatch
          issuerHasTrailingSlash: payload.iss?.endsWith('/'),
          expectedHasTrailingSlash: rodit.metadata.subjectuniqueidentifier_url?.endsWith('/'),
          issuerHasProtocol: payload.iss?.startsWith('http'),
          expectedHasProtocol: rodit.metadata.subjectuniqueidentifier_url?.startsWith('http')
        });
        
        throw new Error("Error 005: Invalid issuer");
      }
      
      // Enhanced logging for audience validation
      logger.debug("Detailed JWT payload for audience validation", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        payload: {
          aud: payload.aud,
          iss: payload.iss,
          sub: payload.sub,
          rodit_id: payload.rodit_id,
          auth_mode: payload.auth_mode,
          auth_context: payload.auth_context,
          jti: payload.jti
        },
        rodit: {
          token_id: rodit.token_id,
          owner_id: rodit.owner_id,
          metadata: {
            serviceprovider_id: rodit.metadata?.serviceprovider_id
          }
        }
      });
      
      // Check if this might be a peer-to-peer authentication attempt
      const isPossiblePeerAuth = 
        (payload.auth_mode === 'peer-to-peer') || 
        (payload.auth_context && payload.auth_context.mode === 'peer-to-peer') ||
        payload.aud.startsWith('peer:') ||
        /^[a-zA-Z0-9]{1,64}\.[a-zA-Z0-9]{1,64}$/.test(payload.aud) ||
        /^[a-z0-9_-]{2,64}(\.near)?$/.test(payload.aud);
      
      logger.debug("Audience validation context", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        tokenAudience: payload.aud,
        expectedAudience: rodit.owner_id,
        isPossiblePeerAuth,
        audienceMatchesOwner: (payload.aud === rodit.owner_id)
      });
      
      if (payload.aud !== rodit.owner_id) {
        logger.warn("Token validation failed - Invalid audience", {
          component: "JwtAuth",
          method: "validate_jwt_token_be",
          requestId,
          tokenAudience: payload.aud,
          expectedAudience: rodit.owner_id,
          isPossiblePeerAuth
        });

        throw new Error("Error 004: Invalid audience");
      }
  
      const totalDuration = Date.now() - startTime;
  
      logger.info("JWT token validation successful", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        duration: totalDuration,
        jti: payload.jti,
        roditId: payload.rodit_id,
      });
  
      // Add metric for successful validations
      logger.metric &&
        logger.metric("jwt_token_validation", totalDuration, {
          result: "success",
          rodit_id: payload.rodit_id,
        });
  
      // Extract user data from payload for middleware
      const user = {
        id: payload.sub,
        roditId: payload.rodit_id,
        ownerId: payload.rodit_owner,
        session: {
          id: payload.session_id,
          status: payload.session_status,
          createdAt: payload.session_iat
            ? new Date(payload.session_iat * 1000).toISOString()
            : "unknown",
          expiresAt: payload.session_exp
            ? new Date(payload.session_exp * 1000).toISOString()
            : "unknown",
        },
        permissions: {
          maxRequests: payload.rodit_maxrequests,
          maxRequestWindow: payload.rodit_maxrqwindow,
          permissionedRoutes: payload.rodit_permissionedroutes,
          allowedCidr: payload.rodit_allowedcidr,
          allowedIso3166List: payload.rodit_allowediso3166list
        },
        webhookUrl: payload.rodit_webhookurl
      };
  
      // Check if token needs renewal or is expired
      const { newToken } = await checkandrenew_jwt_token(payload, Math.floor(Date.now() / 1000), requestId, isExpired);
      
      // If token is expired but we got a new token, consider it valid
      if (isExpired && !newToken) {
        logger.warn("Token expired and renewal failed", {
          component: "JwtAuth",
          method: "validate_jwt_token_be",
          requestId,
          jti: payload.jti
        });
        
        throw new Error("Error 007: Token has expired and renewal failed");
      }
  
      return { 
        payload, 
        peer_rodit,
        valid: true,  // This matches what authenticate_apicall expects
        user,
        newToken
      };
    } catch (error) {
      const duration = Date.now() - startTime;
  
      logger.error("JWT token validation failed", {
        component: "JwtAuth",
        method: "validate_jwt_token_be",
        requestId,
        duration,
        errorCode: error.code,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });
  
      // Add metrics for validation errors
      logger.metric &&
        logger.metric("jwt_token_validation_errors", 1, {
          error_type: error.name || "Unknown",
          error_code: error.code || "none",
        });
  
      logger.metric &&
        logger.metric("jwt_token_validation", duration, {
          result: "failure",
          error_type: error.name || "Unknown",
        });
  
      throw new Error(`JWT token validation failed: ${error.message}`);
    }
  }
  
  /**
   * Brief validation of a JWT token
   *
   * @param {Object} token - Token payload
   * @returns {Promise<Object>} Validation result
   */
  async function brief_validate_jwt_token_be(token) {
    const requestId = ulid();
    const startTime = Date.now();

    logger.debug("Starting brief JWT token validation", {
      component: "JwtAuth",
      method: "brief_validate_jwt_token_be",
      requestId,
      tokenAud: token?.aud,
      tokenJti: token?.jti,
    });

    try {
      const tokenFetchStart = Date.now();
      const peer_rodit =
        await nearorg_rpc_tokensfromaccountid(
          
          token.aud
        );
      const tokenFetchDuration = Date.now() - tokenFetchStart;

      logger.debug("Retrieved peer RODiT", {
        requestId,
        tokenFetchDuration,
        peerRoditId: peer_rodit?.token_id,
        peerRoditOwnerId: peer_rodit?.owner_id,
      });

      const subParts = token.sub.split(";sub=");
      const extractedSub = subParts.length > 1 ? subParts[1] : "";

      logger.debug("Extracted subject from token", {
        requestId,
        extractedSub,
        tokenSub: token.sub,
      });

      const isValid =
        peer_rodit.token_id === extractedSub &&
        peer_rodit.owner_id === token.aud;

      const totalDuration = Date.now() - startTime;

      if (isValid) {
        logger.info("Brief token validation successful", {
          component: "JwtAuth",
          method: "brief_validate_jwt_token_be",
          requestId,
          duration: totalDuration,
          tokenFetchDuration,
          tokenJti: token.jti,
          peerRoditId: peer_rodit.token_id,
          notAfter: peer_rodit.metadata.not_after,
        });

        // Add metrics for successful brief validations
        logger.metric("jwt_brief_validation", totalDuration, {
          result: "success",
          token_jti: token.jti || "unknown",
        });
      } else {
        logger.warn("Brief token validation failed", {
          component: "JwtAuth",
          method: "brief_validate_jwt_token_be",
          requestId,
          duration: totalDuration,
          tokenFetchDuration,
          tokenJti: token.jti,
          peerRoditId: peer_rodit.token_id,
          extractedSub,
          tokenAud: token.aud,
          peerRoditOwnerId: peer_rodit.owner_id,
          idMatch: peer_rodit.token_id === extractedSub,
          ownerMatch: peer_rodit.owner_id === token.aud,
        });

        // Add metrics for failed brief validations
        logger.metric("jwt_brief_validation", totalDuration, {
          result: "failure",
          token_jti: token.jti || "unknown",
          id_match: peer_rodit.token_id === extractedSub ? "true" : "false",
          owner_match: peer_rodit.owner_id === token.aud ? "true" : "false",
        });
      }

      return {
        isValid,
        notAfter: peer_rodit.metadata.not_after,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error("Brief token validation failed with error", {
        component: "JwtAuth",
        method: "brief_validate_jwt_token_be",
        requestId,
        duration,
        tokenAud: token?.aud,
        tokenJti: token?.jti,
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });

      // Add metrics for brief validation errors
      logger.metric("jwt_brief_validation_errors", 1, {
        error_type: error.name || "Unknown",
        token_jti: token.jti || "unknown",
      });

      return {
        isValid: false,
        notAfter: null,
      };
    }
  }

/**
 * Thoroughly validates a JWT token by verifying the associated RODiT
 * Uses a comprehensive verification process with detailed error handling and metrics
 * NOTE: Not checking if the sessions is closed or expired yet.
 * @param {Object} token - The JWT token to validate
 * @returns {Object} - Validation result with isValid flag, notAfter timestamp, and optional verification details
 */
async function thorough_validate_jwt_token_be(token, requestId = ulid()) {
  const startTime = performance.now(); // More precise timing measurement

  logger.debug("Starting thorough JWT token validation", {
    component: "JwtAuth",
    method: "thorough_validate_jwt_token_be",
    requestId,
    tokenRoditId: token?.rodit_id,
    tokenJti: token?.jti,
  });

  try {
    // Fetch configuration with better timing measurements
    const configStart = performance.now();
    const config_own_rodit = await stateManager.getConfigOwnRodit();
    const configDuration = performance.now() - configStart;

    logger.debug("Retrieved configuration", {
      requestId,
      configDuration,
      hasConfig: !!config_own_rodit,
      ownRoditId: config_own_rodit?.own_rodit?.token_id,
    });

    // Fetch peer RODiT with clearer logging
    const tokenFetchStart = performance.now();
    const peer_rodit = await nearorg_rpc_tokenfromroditid(token.rodit_id);
    const tokenFetchDuration = performance.now() - tokenFetchStart;

    logger.debug("Retrieved peer RODiT from blockchain", {
      requestId,
      tokenFetchDuration,
      hasPeerRodit: !!peer_rodit,
      peerRoditId: peer_rodit?.token_id,
      peerRoditOwnerId: peer_rodit?.owner_id,
      hasPeerRoditMetadata: peer_rodit && !!peer_rodit.metadata,
      metadataKeys: peer_rodit && peer_rodit.metadata ? Object.keys(peer_rodit.metadata) : [],
    });

    if (!peer_rodit) {
      logger.error("Failed to retrieve peer RODiT data", {
        component: "JwtAuth",
        requestId,
        duration: performance.now() - startTime,
        tokenRoditId: token?.rodit_id,
      });

      // Add metrics for failed token fetch
      logger.metric &&
        logger.metric("jwt_thorough_validation", performance.now() - startTime, {
          result: "rodit_fetch_failed",
          token_jti: token.jti || "unknown",
        });

      return {
        isValid: false,
        notAfter: null,
      };
    }

    if (!peer_rodit.metadata) {
      logger.error("Peer RODiT missing metadata", {
        component: "JwtAuth",
        requestId,
        duration: performance.now() - startTime,
        tokenRoditId: token?.rodit_id,
        peerRoditId: peer_rodit.token_id,
        peerRoditOwnerId: peer_rodit.owner_id,
      });

      // Add metrics for missing metadata
      logger.metric &&
        logger.metric("jwt_thorough_validation", performance.now() - startTime, {
          result: "missing_metadata",
          token_jti: token.jti || "unknown",
          peer_rodit_id: peer_rodit.token_id,
        });

      return {
        isValid: false,
        notAfter: null,
      };
    }

    // Starting verification with more detailed logging
    logger.debug("Starting verification checks", {
      requestId,
      checks: ["match", "live", "active", "trusted"],
      serviceProviderId: config_own_rodit.own_rodit.metadata.serviceprovider_id,
    });

    // Import verification functions dynamically to avoid circular dependencies
    const { 
      verify_rodit_isamatch,
      verify_rodit_islive,
      verify_rodit_isactive,
      verify_rodit_istrusted_issuingsmartcontract
    } = require("./authentication");

    // Perform match verification
    const matchStart = performance.now();
    const isaMatch = await verify_rodit_isamatch(
      config_own_rodit.own_rodit.metadata.serviceprovider_id,
      peer_rodit
    );
    const matchDuration = performance.now() - matchStart;

    logger.debug("Match verification completed", {
      requestId,
      matchDuration,
      isaMatch,
      serviceProviderId: config_own_rodit.own_rodit.metadata.serviceprovider_id,
      peerServiceProviderId: peer_rodit.metadata.serviceprovider_id,
    });

    if (!isaMatch) {
      logger.warn("RODiT match verification failed", {
        component: "JwtAuth",
        method: "thorough_validate_jwt_token_be",
        requestId,
        duration: performance.now() - startTime,
        serviceProviderId: config_own_rodit.own_rodit.metadata.serviceprovider_id,
        peerServiceProviderId: peer_rodit.metadata.serviceprovider_id,
      });

      // Add metrics for failed match verification
      logger.metric &&
        logger.metric("jwt_thorough_validation", performance.now() - startTime, {
          result: "match_failed",
          token_jti: token.jti || "unknown",
          peer_rodit_id: peer_rodit.token_id,
        });

      return {
        isValid: false,
        notAfter: null,
        error: "RODiT match verification failed",
      };
    }

    // Perform live verification
    const liveStart = performance.now();
    const isLive = await verify_rodit_islive(
      peer_rodit.metadata.not_after,
      peer_rodit.metadata.not_before
    );
    const liveDuration = performance.now() - liveStart;

    logger.debug("Live verification completed", {
      requestId,
      liveDuration,
      isLive,
      notAfter: peer_rodit.metadata.not_after,
      notBefore: peer_rodit.metadata.not_before,
    });

    if (!isLive) {
      logger.warn("RODiT live verification failed", {
        component: "JwtAuth",
        method: "thorough_validate_jwt_token_be",
        requestId,
        duration: performance.now() - startTime,
        notAfter: peer_rodit.metadata.not_after,
        notBefore: peer_rodit.metadata.not_before,
      });

      // Add metrics for failed live verification
      logger.metric &&
        logger.metric("jwt_thorough_validation", performance.now() - startTime, {
          result: "live_failed",
          token_jti: token.jti || "unknown",
          peer_rodit_id: peer_rodit.token_id,
        });

      return {
        isValid: false,
        notAfter: null,
        error: "RODiT live verification failed",
      };
    }

    // Perform active verification
    const activeStart = performance.now();
    const isActive = await verify_rodit_isactive(
      peer_rodit.token_id,
      config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url
    );
    const activeDuration = performance.now() - activeStart;

    logger.debug("Active verification completed", {
      requestId,
      activeDuration,
      isActive,
      tokenId: peer_rodit.token_id,
      url: config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url,
    });

    if (!isActive) {
      logger.warn("RODiT active verification failed", {
        component: "JwtAuth",
        method: "thorough_validate_jwt_token_be",
        requestId,
        duration: performance.now() - startTime,
        tokenId: peer_rodit.token_id,
        url: config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url,
      });

      // Add metrics for failed active verification
      logger.metric &&
        logger.metric("jwt_thorough_validation", performance.now() - startTime, {
          result: "active_failed",
          token_jti: token.jti || "unknown",
          peer_rodit_id: peer_rodit.token_id,
        });

      return {
        isValid: false,
        notAfter: null,
        error: "RODiT active verification failed",
      };
    }

    // Perform trusted verification
    const trustedStart = performance.now();
    const isTrusted = await verify_rodit_istrusted_issuingsmartcontract(
      config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url
    );
    const trustedDuration = performance.now() - trustedStart;

    logger.debug("Trust verification completed", {
      requestId,
      trustedDuration,
      isTrusted,
      url: config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url,
    });

    if (!isTrusted) {
      logger.warn("RODiT trust verification failed", {
        component: "JwtAuth",
        method: "thorough_validate_jwt_token_be",
        requestId,
        duration: performance.now() - startTime,
        url: config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url,
      });

      // Add metrics for failed trust verification
      logger.metric &&
        logger.metric("jwt_thorough_validation", performance.now() - startTime, {
          result: "trust_failed",
          token_jti: token.jti || "unknown",
          peer_rodit_id: peer_rodit.token_id,
        });

      return {
        isValid: false,
        notAfter: null,
        error: "RODiT trust verification failed",
      };
    }

    // Extract subject and perform final validation
    const subParts = token.sub.split(";sub=");
    const extractedSub = subParts.length > 1 ? subParts[1] : "";

    logger.debug("Extracted subject from token", {
      requestId,
      extractedSub,
      tokenSub: token.sub,
      peerRoditId: peer_rodit.token_id,
      peerRoditOwnerId: peer_rodit.owner_id,
      tokenAud: token.aud,
    });

    // Additional identity checks
    const idMatch = peer_rodit.token_id === extractedSub;
    const ownerMatch = peer_rodit.owner_id === token.aud;
    const isValid = idMatch && ownerMatch;

    const totalDuration = performance.now() - startTime;

    if (isValid) {
      logger.info("Thorough token validation successful", {
        component: "JwtAuth",
        method: "thorough_validate_jwt_token_be",
        requestId,
        duration: totalDuration,
        tokenJti: token.jti,
        peerRoditId: peer_rodit.token_id,
        notAfter: peer_rodit.metadata.not_after,
      });

      // Add metrics for successful thorough validations
      logger.metric &&
        logger.metric("jwt_thorough_validation", totalDuration, {
          result: "success",
          token_jti: token.jti || "unknown",
          peer_rodit_id: peer_rodit.token_id,
        });
    } else {
      const failedIdentityChecks = [];
      if (!idMatch) failedIdentityChecks.push("token_id_mismatch");
      if (!ownerMatch) failedIdentityChecks.push("owner_id_mismatch");

      logger.warn("Token identity verification failed", {
        component: "JwtAuth",
        method: "thorough_validate_jwt_token_be",
        requestId,
        duration: totalDuration,
        tokenJti: token.jti,
        extractedSub,
        peerRoditId: peer_rodit.token_id,
        tokenAud: token.aud,
        peerRoditOwnerId: peer_rodit.owner_id,
        idMatch,
        ownerMatch,
        failedIdentityChecks,
      });

      // Add metrics for identity mismatch with more details
      logger.metric &&
        logger.metric("jwt_thorough_validation", totalDuration, {
          result: "identity_mismatch",
          token_jti: token.jti || "unknown",
          id_match: idMatch ? "true" : "false",
          owner_match: ownerMatch ? "true" : "false",
          failed_checks: failedIdentityChecks.join(","),
          peer_rodit_id: peer_rodit.token_id,
        });
    }

    return {
      isValid,
      notAfter: peer_rodit.metadata.not_after,
    };
  } catch (error) {
    const duration = performance.now() - startTime;

    logger.error("Thorough token validation failed with error", {
      component: "JwtAuth",
      method: "thorough_validate_jwt_token_be",
      requestId,
      duration,
      tokenRoditId: token?.rodit_id,
      tokenJti: token?.jti,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
        code: error.code || 'unknown',
      },
    });

    // Add more detailed metrics for thorough validation errors
    logger.metric &&
      logger.metric("jwt_thorough_validation", duration, {
        result: "error",
        error_type: error.name || "Unknown",
        error_code: error.code || "unknown",
        token_jti: token?.jti || "unknown",
      });

    return {
      isValid: false,
      notAfter: null,
      error: error.message,
    };
  }
}

  /**
   * Check if a token needs renewal and renew if necessary
   *
   * @param {Object} payload - Token payload
   * @param {number} timestamp - Current timestamp
   * @param {string} requestId - Request ID for tracking
   * @returns {Promise<Object>} Renewal result with new token if renewed
   */
  async function checkandrenew_jwt_token(payload, timestamp, requestId, forceRenewal = false) {
    const startTime = Date.now();
    const config_own_rodit = await stateManager.getConfigOwnRodit();

    // Parse config values ensuring they're numbers
    const LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY = parseFloat(
      config_own_rodit.tokenrenewaloptions
        .LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY || 0.15
    );
    const THRESHOLD_VALIDATION_TYPE = parseFloat(
      config_own_rodit.tokenrenewaloptions.THRESHOLD_VALIDATION_TYPE || 0.25
    );
    const DURATIONRAMP = parseFloat(
      config_own_rodit.tokenrenewaloptions.DURATIONRAMP || 1.0
    );

    const currentTime = Math.floor(Date.now() / 1000);
    const timeLeft = payload.exp - currentTime;
    const currentDuration = payload.exp - payload.iat;
    const durationLeftpct = (timeLeft / currentDuration) * 100;
    const newduration = currentDuration * DURATIONRAMP;

    // Log session information
    const sessionInfo = {
      sessionId: payload.session_id || "none",
      sessionStatus: payload.session_status || "unknown",
      sessionCreatedAt: payload.session_iat
        ? new Date(payload.session_iat * 1000).toISOString()
        : "unknown",
      sessionAge: payload.session_iat
        ? Math.floor(currentTime - payload.session_iat)
        : "unknown",
    };

    logger.debug("Checking token for proactive renewal", {
      component: "TokenRenewalService",
      method: "checkandrenew_jwt_token",
      requestId,
      timeLeftPercent: durationLeftpct.toFixed(1),
      timeLeftSeconds: timeLeft,
      tokenId: payload.jti || "unknown",
      ...sessionInfo,
    });

    // No renewal needed if above threshold and not forced
    if (
      !forceRenewal &&
      durationLeftpct / 100 >=
        1.0 - LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY
    ) {
      const renewThresholdPercent = (
        100 - (LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY * 100)
      ).toFixed(1);
      const renewThresholdSeconds =
        currentDuration * (1 - LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY);
      const secondsUntilEligibility = Math.max(
        0,
        timeLeft - renewThresholdSeconds
      );
      const eligibilityTimestamp = new Date(
        (currentTime + secondsUntilEligibility) * 1000
      ).toISOString();

      logger.debug("Token has not met renewal threshold yet", {
        component: "TokenRenewalService",
        method: "checkandrenew_jwt_token",
        requestId,
        timeLeftPercent: durationLeftpct.toFixed(1),
        renewThresholdPercent,
        secondsUntilEligibility,
        eligibilityTimestamp,
        renewalConditions: {
          minimumLapsedLifetimePercent:
            LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY * 100,
          requiredRemainingPercent: renewThresholdPercent,
        },
      });

      const duration = Date.now() - startTime;
      logger.metric("token_renewal_check_duration_ms", duration, {
        component: "TokenRenewalService",
        renewalNeeded: false,
        session_status: payload.session_status || "unknown",
      });
      logger.metric("tokens_not_renewed_total", 1, {
        component: "TokenRenewalService",
        reason: "sufficient_lifetime",
        session_status: payload.session_status || "unknown",
        seconds_until_eligibility: secondsUntilEligibility,
      });
      return { newToken: null };
    }

    // Token needs renewal
    logger.info(forceRenewal ? "Token expired, attempting renewal" : "Token eligible for proactive renewal", {
      component: "TokenRenewalService",
      method: "checkandrenew_jwt_token",
      requestId,
      timeLeftPercent: durationLeftpct.toFixed(1),
      renewThreshold: (
        100 - (LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY * 100)
      ).toFixed(1),
      ...sessionInfo,
    });

    // Determine verification method
    const randomNumber = Math.random();
    const shouldDoFullVerification =
      randomNumber < THRESHOLD_VALIDATION_TYPE ||
      newduration >
        payload.rodit_maxrqwindow *
          (100 - (LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY * 100));

    const verificationStartTime = Date.now();

    // Determine verification level for renewal
    const verification_level = shouldDoFullVerification ? "full" : "light";

    logger.debug("Validation strategy decision", {
      component: "TokenRenewalService",
      method: "checkandrenew_jwt_token",
      requestId,
      randomValue: randomNumber,
      threshold: THRESHOLD_VALIDATION_TYPE,
      durationCheck:
        newduration >
        payload.rodit_maxrqwindow *
          (100 - (LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY * 100)),
      useFullVerification: shouldDoFullVerification,
      verificationLevel: verification_level,
      renewalConfig: {
        lapsedProportion: LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY,
        validationThreshold: THRESHOLD_VALIDATION_TYPE,
        durationRamp: DURATIONRAMP,
      },
    });

    try {
      let isValid = false;
      let notAfter = null;

      if (shouldDoFullVerification) {
        logger.debug("Performing thorough token verification", {
          component: "TokenRenewalService",
          method: "checkandrenew_jwt_token",
          requestId,
          reason:
            randomNumber < THRESHOLD_VALIDATION_TYPE
              ? "random_threshold"
              : "duration_threshold",
          verificationLevel: "full",
        });

        const validationResult = await thorough_validate_jwt_token_be(
          payload,
          requestId
        );

        isValid = validationResult.isValid;
        notAfter = validationResult.notAfter;

        const verificationDuration = Date.now() - verificationStartTime;
        logger.metric("token_verification_duration_ms", verificationDuration, {
          component: "TokenRenewalService",
          verificationType: "thorough",
          success: isValid,
        });
      } else {
        // Light verification path
        logger.debug("Performing brief token verification", {
          component: "TokenRenewalService",
          method: "checkandrenew_jwt_token",
          requestId,
          verificationLevel: "light",
        });

        const validationResult = await brief_validate_jwt_token_be(
          payload, 
        );

        isValid = validationResult.isValid;
        notAfter = validationResult.notAfter;

        const verificationDuration = Date.now() - verificationStartTime;
        logger.metric("token_verification_duration_ms", verificationDuration, {
          component: "TokenRenewalService",
          verificationType: "brief",
          success: isValid,
        });
      }

      if (isValid) {
        const renewalStartTime = Date.now();
        const newToken = await generate_jwt_token_fromtoken(
          payload,
          newduration,
          notAfter,
          timestamp,
          shouldDoFullVerification ? "full" : "light"
        );

        const renewalDuration = Date.now() - renewalStartTime;
        const totalDuration = Date.now() - startTime;

        logger.info("Proactive token renewal successful", {
          component: "TokenRenewalService",
          method: "checkandrenew_jwt_token",
          requestId,
          verificationType: shouldDoFullVerification ? "thorough" : "brief",
          renewalDuration,
          totalDuration,
          newDuration: newduration,
          sessionStatus: shouldDoFullVerification
            ? "renewed_full_verification"
            : "renewed_light_verification",
        });

        // Emit metrics for successful renewal
        logger.metric("token_renewal_duration_ms", renewalDuration, {
          component: "TokenRenewalService",
          success: true,
          verificationType: shouldDoFullVerification ? "thorough" : "brief",
          verification_level: shouldDoFullVerification ? "full" : "light",
          session_status: shouldDoFullVerification
            ? "renewed_full_verification"
            : "renewed_light_verification",
        });

        return {
          newToken,
          logInfo: {
            newDuration: newduration,
            reason: shouldDoFullVerification
              ? "Thorough verification"
              : "Brief verification",
            notAfter: notAfter,
            renewalDuration,
            totalDuration,
            verificationLevel: shouldDoFullVerification ? "full" : "light",
            sessionStatus: shouldDoFullVerification
              ? "renewed_full_verification"
              : "renewed_light_verification",
          },
        };
      }
    } catch (error) {
      logger.error("Token renewal failed", {
        component: "TokenRenewalService",
        method: "checkandrenew_jwt_token",
        requestId,
        error: error.message,
      });
    }

    // If we reach here, renewal wasn't successful
    const totalDuration = Date.now() - startTime;
    logger.debug("Token renewal not performed", {
      component: "TokenRenewalService",
      method: "checkandrenew_jwt_token",
      requestId,
      totalDuration,
      sessionId: payload.session_id || "none",
    });

    logger.metric("token_renewal_check_duration_ms", totalDuration, {
      component: "TokenRenewalService",
      renewalNeeded: true,
      success: false,
      session_status: payload.session_status || "unknown",
    });

    return { newToken: null };
  }


// Export the class directly (will be instantiated in rodit.js)
module.exports = {generate_jwt_token,base64url2jwk_public_key,
  checkandrenew_jwt_token,
  thorough_validate_jwt_token_be,
  brief_validate_jwt_token_be,
  generate_jwt_token_fromtoken,
  verify_jwt_token,validate_jwt_token_be, generate_session_termination_token
};
