/**
 * Permission validation middleware
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const crypto = require("crypto");
const { ulid } = require("ulid");
const config = require('../../services/configsdk');

// Dynamic import for ESM 'jose' in CommonJS context
let _josePromise;
async function getJose() {
  if (!_josePromise) {
    _josePromise = import("jose");
  }
  return _josePromise;
}

class PermissionValidator {
  constructor() {
    // Load method permission map from config or use default if not available
    this.methodPermissionMap = config.get('METHOD_PERMISSION_MAP');
  }

  /**
   * Parse the rate value from the permission string
   * 
   * @param {string} rateValue - The permission value from the token (e.g., "+0")
   * @returns {Object} An object containing the rate limit and whether it's unlimited
   *                  { limit: number|null, unlimited: boolean }
   */
  parseRateLimit(rateValue) {
    // Skip if no value or not a string
    if (!rateValue || typeof rateValue !== 'string') {
      return { limit: null, unlimited: false };
    }
    
    // Remove the permission prefix (+ or -)
    let rateString = rateValue;
    if (rateString.startsWith('+') || rateString.startsWith('-')) {
      rateString = rateString.substring(1);
    }
    
    // Try to parse the rate as a number (could be in scientific notation)
    try {
      const rate = parseFloat(rateString);
      
      // Check if it's a valid number
      if (isNaN(rate)) {
        return { limit: null, unlimited: false };
      }
      
      // Special case: 0 indicates no limits
      if (rate === 0) {
        return { limit: null, unlimited: true };
      }
      
      // Return the actual rate limit
      return { limit: rate, unlimited: false };
    } catch (e) {
      return { limit: null, unlimited: false };
    }
  }

  /**
   * Determine the permission scope from the rate value prefix
   * 
   * @param {string} rateValue - The permission value from the token (e.g., "+0")
   * @returns {string} The permission scope (entityAndProperties, propertiesOnly, or entityOnly)
   */
  getPermissionScope(rateValue) {
    if (rateValue.startsWith("+")) {
      return "entityAndProperties";
    } else if (rateValue.startsWith("-")) {
      return "propertiesOnly";
    }
    return "entityOnly";
  }

  isMethodAllowed(method, permissionScope) {
    const startTime = Date.now();
    const requestId = ulid();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "PermissionValidator",
      "isMethodAllowed",
      {
        requestId,
        requestedMethod: method,
        permissionScope
      }
    );

    if (!this.methodPermissionMap[method]) {
      logErrorWithMetrics(
        "Unknown method detected", 
        {
          ...baseContext,
          duration: Date.now() - startTime
        },
        new Error(`Unknown method: ${method}`),
        "permission_validation_error",
        { error_type: "unknown_method" }
      );
      return false;
    }

    const isAllowed =
      this.methodPermissionMap[method].includes(permissionScope);

    logger.debugWithContext("Method permission check completed", {
      ...baseContext,
      isAllowed,
      duration: Date.now() - startTime
    });

    return isAllowed;
  }

  findMatchingEntity(entities, fullPath, requestId) {
    const startTime = Date.now();
    // Use provided requestId or generate a new one
    const contextRequestId = requestId || ulid();

    // Handle entities as an object with name and methods
    const entity = entities.name;
    const methods = entities.methods;
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "PermissionValidator",
      "findMatchingEntity",
      {
        requestId: contextRequestId,
        fullPath,
        entity
      }
    );
    
    // Log available methods for debugging
    logger.debugWithContext("Checking permission for path", {
      ...baseContext,
      availableMethods: Object.keys(methods)
    });

    // Check for an exact match in the methods
    if (methods.hasOwnProperty(fullPath)) {
      const rateValue = methods[fullPath];
      // Extract the operation name (last part of the path)
      const operation = fullPath.split("/").pop();

      logger.infoWithContext("Processing permission request", {
        ...baseContext,
        requestedMethod: operation,
      });

      const permissionScope = this.getPermissionScope(rateValue);
      const isPermitted = this.isMethodAllowed(operation, permissionScope);

      logger.debugWithContext("Permission check result", {
        ...baseContext,
        requestedMethod: operation,
        permissionScope,
        rateValue,
        isPermitted,
        duration: Date.now() - startTime
      });

      if (isPermitted) {
        // Parse the rate limit from the permission value
        const rateLimitInfo = this.parseRateLimit(rateValue);
        
        return {
          isPermitted: true,
          commentsRate: rateValue,
          permissionScope,
          rateLimit: rateLimitInfo.limit,
          unlimited: rateLimitInfo.unlimited,
          operation, // Add the operation name for future rate limiting
        };
      }
    }
    
    // No special handling for session routes - all routes must be explicitly defined in the token

    logger.warnWithContext("No matching permission found", {
      ...baseContext,
      duration: Date.now() - startTime
    });

    return {
      isPermitted: false,
      commentsRate: null,
      permissionScope: null,
    };
  }

  async validate(req) {
    const requestId = req.headers["x-request-id"] || ulid();
    const startTime = Date.now();
    
    // Create a base context for this method
    const baseContext = createLogContext(
      "PermissionValidator",
      "validate",
      {
        requestId,
        path: req.path,
        method: req.method,
        ip: req.ip
      }
    );

    const token = req.header("Authorization");
    if (!token) {
      logger.warnWithContext("Authorization token missing", {
        ...baseContext,
        userAgent: req.headers["user-agent"],
        duration: Date.now() - startTime
      });

      return {
        isValid: false,
        status: 401,
        message: "Access denied. No token provided.",
      };
    }

    try {
      const { decodeJwt } = await getJose();
      const decodedToken = decodeJwt(token);
      
      // Update context with user information
      const contextWithUser = {
        ...baseContext,
        userId: decodedToken.sub || "unknown"
      };

      logger.infoWithContext("Endpoint access attempt", contextWithUser);

      let permissionedRoutes;
      try {
        if (typeof decodedToken.rodit_permissionedroutes === 'string') {
          permissionedRoutes = JSON.parse(decodedToken.rodit_permissionedroutes);
        } else {
          permissionedRoutes = decodedToken.rodit_permissionedroutes;
        }
      } catch (error) {
        logErrorWithMetrics(
          "Failed to parse permissioned routes", 
          contextWithUser,
          error,
          "permission_validation_error",
          { 
            error_type: "parse_error",
            permissionedRoutesType: typeof decodedToken.rodit_permissionedroutes,
            valuePreview: decodedToken.rodit_permissionedroutes ? 
              decodedToken.rodit_permissionedroutes.substring(0, 100) : "undefined"
          }
        );
        throw error;
      }

      // Add debug logging for permission routes content
      logger.debugWithContext("Permission routes content", {
        ...contextWithUser,
        permissionedRoutes: JSON.stringify(permissionedRoutes).substring(0, 200) + "..."
      });

      // Use entities directly, assuming it's an object
      const entities = permissionedRoutes.entities;
      
      // Construct the full path for permission checking
      // This must exactly match what's defined in the RODiT token
      let fullPath = req.baseUrl + req.path;
      
      // Normalize path by removing trailing slashes (except for root path)
      // This handles common URL variations like /api/list_agents vs /api/agents/
      if (fullPath.length > 1 && fullPath.endsWith('/')) {
        fullPath = fullPath.slice(0, -1);
      }
      
      logger.debugWithContext("Validating permission for full path", {
        ...contextWithUser,
        baseUrl: req.baseUrl,
        path: req.path,
        fullPath
      });
      
      const { isPermitted, commentsRate, permissionScope, rateLimit, operation } =
        this.findMatchingEntity(entities, fullPath, requestId);

      if (!isPermitted) {
        logger.warnWithContext("Permission denied", {
          ...contextWithUser,
          path: req.path,
          fullPath,
          userId: decodedToken.sub || "unknown",
          duration: Date.now() - startTime,
          requestId,
        });

        return {
          isValid: false,
          status: 403,
          message: "Permission denied",
        };
      }

      logger.infoWithContext("Authorization successful", {
        ...contextWithUser,
        fullPath,
        permissionScope,
        rateValue: commentsRate,
        duration: Date.now() - startTime
      });

      return {
        isValid: true,
        commentsRate,
        permissionScope,
        rateLimit,
        operation
      };
    } catch (error) {
      // Use logErrorWithMetrics for better error tracking
      logErrorWithMetrics(
        "Permission check failed", 
        {
          ...baseContext,
          duration: Date.now() - startTime
        },
        error,
        "permission_validation_error",
        { 
          error_type: "validation_error",
          errorCode: "112"
        }
      );

      return {
        isValid: false,
        status: 400,
        message: "Error 119: Invalid token or permissions.",
      };
    }
  }
}

const permissionValidator = new PermissionValidator();

/**
 * @swagger
 * /authorize:
 *   get:
 *     summary: Authorize user and check JWT token fields
 *     description: Verify the JWT token and check specific fields before granting access
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Authorization successful
 *       401:
 *         description: Unauthorized - Invalid token or missing required fields
 */
async function validatepermissions(req, res, next) {
  const startTime = Date.now();
  const requestId = req.headers["x-request-id"] || ulid();

  if (!req.headers["x-request-id"]) {
    req.headers["x-request-id"] = requestId;
  }
  
  // Create a base context for this middleware
  const baseContext = createLogContext(
    "validatepermissions",
    "middleware",
    {
      requestId,
      path: req.path,
      baseUrl: req.baseUrl,
      fullPath: req.baseUrl + req.path,
      method: req.method,
      ip: req.ip
    }
  );

  logger.debugWithContext("Permission validation started", baseContext);

  const result = await permissionValidator.validate(req);

  if (!result.isValid) {
    logger.warnWithContext("Permission validation failed", {
      ...baseContext,
      status: result.status,
      message: result.message,
      duration: Date.now() - startTime
    });

    return res.status(result.status).json({ message: result.message });
  }

  if (result.commentsRate) {
    req.commentsRate = result.commentsRate;
  }
  
  // Make rate limit information available for future implementation
  req.rateLimit = {
    value: result.rateLimit,
    unlimited: result.unlimited === true,
    operation: result.operation,
    path: req.path,
    timeWindow: 60 // Default time window in seconds
  };
  
  req.permissionScope = result.permissionScope;

  logger.debugWithContext("Permission validation successful", {
    ...baseContext,
    permissionScope: result.permissionScope,
    duration: Date.now() - startTime
  });

  next();
}

module.exports = validatepermissions;