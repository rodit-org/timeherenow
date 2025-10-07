// In the protected/signclient.js file
const express = require("express");
const router = express.Router();
const { ulid } = require("ulid");
// Use npm package exports
const { logger, roditManager } = require("@rodit/rodit-auth-be");
// login_portal method is now available on the RoditClient instance stored in app.locals
const { createLogContext, logErrorWithMetrics } = logger;

async function signPortalRodit(
  port,
  tamperproofedValues,
  mintingfee,
  mintingfeeaccount,
  roditClient
) {
  const requestId = ulid();
  const startTime = Date.now();
  
  // Create context objects for structured logging
  const baseContext = createLogContext({
    requestId,
    component: "SignPortal",
    method: "signPortalRodit",
    serviceProviderId: tamperproofedValues.serviceprovider_id,
    port
  });

  logger.debugWithContext("Sending signportal request", baseContext);

  // Get API endpoint using the roditClient's getPortalUrl method
  const apiendpoint = roditClient.getPortalUrl(
    tamperproofedValues.serviceprovider_id,
    port
  );

  const signportalJwtToken = roditClient.getSignPortalJwtToken();
  const requestBody = {
    tamperproofedValues,
    mintingfee,
    mintingfeeaccount,
  };

  const fetchUrl = `${apiendpoint}/api/portal/signportal`;
  
  const headers = {
    "Content-Type": "application/json",
    "X-Request-ID": requestId,
  };

  if (signportalJwtToken) {
    headers["Authorization"] = `Bearer ${signportalJwtToken}`;
  }

  // Enhanced logging with structured context
  const apiCallContext = {
    ...baseContext,
    url: fetchUrl,
    headers: Object.keys(headers),
    bodySize: JSON.stringify(requestBody).length,
    hasToken: !!signportalJwtToken
  };
  
  logger.infoWithContext("Preparing SignPortal API call", apiCallContext);
  
  // Separate sensitive data into debug level logs
  logger.debugWithContext("Request body details", {
    ...baseContext,
    bodyKeys: Object.keys(requestBody)
  });

  try {
    const result = await roditClient.fetchWithErrorHandlingSignPortal(fetchUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
    });

    const duration = Date.now() - startTime;
    logger.infoWithContext("Raw response received from SignPortal", {
      ...baseContext,
      responseReceived: true,
      duration
    });

    if (result.error) {
      const duration = Date.now() - startTime;
      
      logErrorWithMetrics(
        "SignPortal error response",
        {
          ...baseContext,
          errorCode: result.error,
          errorMessage: result.message,
          duration
        },
        new Error(`SignPortal error: ${result.error}: ${result.message}`),
        "signportal_error",
        {
          operation: "signPortalRodit",
          result: "error",
          duration
        }
      );
      
      throw new Error(`SignPortal error: ${result.error}: ${result.message}`);
    }

    const successDuration = Date.now() - startTime;
    logger.infoWithContext("SignPortal operation successful", {
      ...baseContext,
      tokenId: result.token_id,
      duration: successDuration
    });
    
    // Add metric for successful operation
    logger.metric("signportal_operations", successDuration, {
      operation: "signPortalRodit",
      result: "success"
    });
    
    return result;
  } catch (error) {
    const errorDuration = Date.now() - startTime;
    
    logErrorWithMetrics(
      "Error during signportal operation",
      {
        ...baseContext,
        errorMessage: error.message,
        duration: errorDuration
      },
      error,
      "signportal_error",
      {
        operation: "signPortalRodit",
        result: "error",
        duration: errorDuration
      }
    );
    
    throw error;
  }
}

// Ensure body parsing for this route specifically
router.use(express.json());
router.use(express.urlencoded({ extended: false }));

// The signclient endpoint that the frontend will call
router.post("/signclient", async (req, res) => {
  const requestId = ulid();
  const startTime = Date.now();
  
  // Create base context object for consistent logging
  const baseContext = createLogContext({
    requestId,
    component: "SignClient",
    method: "handleSignClientRequest",
    endpoint: "/signclient",
    httpMethod: req.method,
    ip: req.ip,
    userAgent: req.get("User-Agent")
  });
  
  logger.infoWithContext("Received signclient request", baseContext);

  // Debug request body and headers
  logger.debugWithContext("Request debugging info", {
    ...baseContext,
    hasBody: !!req.body,
    bodyType: typeof req.body,
    bodyContent: req.body,
    contentType: req.get('Content-Type'),
    contentLength: req.get('Content-Length'),
    allHeaders: Object.keys(req.headers || {}),
    rawBody: req.rawBody || 'not available'
  });

  try {
    // Check if req.body exists before destructuring
    if (!req.body) {
      logger.errorWithContext("Request body is undefined", {
        ...baseContext,
        contentType: req.get('Content-Type'),
        contentLength: req.get('Content-Length'),
        method: req.method,
        headers: req.headers
      });
      
      return res.status(400).json({
        error: "Request body is missing or malformed",
        details: "Expected JSON body with tobesignedValues, mintingfee, and mintingfeeaccount",
        requestId,
        contentType: req.get('Content-Type')
      });
    }

    // Get data from frontend
    const { tobesignedValues, mintingfee, mintingfeeaccount } = req.body;

    // Enhanced context with request validation
    const validationContext = {
      ...baseContext,
      hasSignedValues: !!tobesignedValues,
      hasMintingFee: !!mintingfee,
      hasMintingFeeAccount: !!mintingfeeaccount,
      bodySize: req.body ? JSON.stringify(req.body).length : 0
    };

    // Basic validation
    if (!tobesignedValues || !mintingfee || !mintingfeeaccount) {
      logger.warnWithContext("Missing required fields in signclient request", validationContext);

      return res.status(400).json({
        error: "Missing required fields",
        requestId,
      });
    }

    // Initialize vault and config if not already done
    if (!roditManager.vaultInitialized) {
      logger.infoWithContext("Initializing vault for signclient", baseContext);
      await roditManager.initializeCredentialsStore();
      await roditManager.initializeRoditConfig("server");
    }

    // Get configuration from hash data
    const roditClient = req.app.locals.roditClient;
    if (!roditClient) {
      throw new Error('RoditClient not available in app.locals');
    }
    const config_own_rodit = await roditClient.getConfigOwnRodit();
    if (!config_own_rodit) {
      logger.errorWithContext("Failed to get RODiT configuration", baseContext);
      throw new Error("Failed to initialize RODiT configuration");
    }

    const portalPort = 8443;
    
    // JWT Token management
    // roditClient already defined above
    const jwtContext = {
      ...baseContext,
      portalPort,
      hasExistingToken: !!roditClient.getSignPortalJwtToken()
    };
    
    if (!roditClient.getSignPortalJwtToken()) {
      logger.infoWithContext("Authenticating with SignPortal", jwtContext);

      // Use the login_portal method on the roditClient instance
      const loginResult = await roditClient.login_portal(config_own_rodit, portalPort);

      if (!loginResult.jwt_token) {
        // Enhanced error logging with clear cause and effect
        const errorDetails = loginResult.error || "Unknown error";
        const errorReason = loginResult.reason || "Connection to SignPortal failed";
        
        logger.errorWithContext("Failed to obtain JWT token: Authentication with SignPortal failed", {
          ...jwtContext,
          errorDetails,
          errorReason,
          impact: "Cannot proceed with client authentication flow"
        });
        
        throw new Error(`Failed to obtain JWT token from SignPortal: ${errorReason}`);
      }

      await roditClient.setSignPortalJwtToken(loginResult.jwt_token);
      logger.infoWithContext("Successfully authenticated with SignPortal", jwtContext);
    }

    // Validate that all requested permissions exist in the server's configuration
    try {
      // Parse the requested permissions and the configuration permissions
      const requestedPermissions = JSON.parse(tobesignedValues.permissioned_routes);
      const configPermissions = JSON.parse(config_own_rodit.own_rodit.metadata.permissioned_routes);
      
      // Extract methods from both objects
      const requestedMethods = requestedPermissions?.entities?.methods || {};
      const configMethods = configPermissions?.entities?.methods || {};
      
      // Check for any requested routes that don't exist in the config
      const invalidRoutes = [];
      for (const route of Object.keys(requestedMethods)) {
        if (!configMethods.hasOwnProperty(route)) {
          invalidRoutes.push(route);
          logger.warnWithContext("Invalid route permission requested", {
            ...baseContext,
            route,
            permission: requestedMethods[route],
            reason: "not_in_config"
          });
        } else {
          logger.debugWithContext("Valid route permission requested", {
            ...baseContext,
            route,
            permission: requestedMethods[route],
            reason: "present_in_config"
          });
        }
      }
      
      // If there are any invalid routes, reject the request
      if (invalidRoutes.length > 0) {
        const errorMessage = `Invalid permission(s) requested: ${invalidRoutes.join(', ')}`;
        logger.errorWithContext("Permission validation failed - rejecting signing request", {
          ...baseContext,
          invalidRoutes,
          requestedRouteCount: Object.keys(requestedMethods).length,
          configRouteCount: Object.keys(configMethods).length,
          error: errorMessage
        });
        
        return res.status(400).json({
          error: "Invalid permissions requested",
          details: {
            invalidRoutes,
            message: "One or more requested permissions are not available in the server's configuration",
            availableRoutes: Object.keys(configMethods)
          },
          requestId: req.requestId
        });
      }
      
      logger.infoWithContext("All requested permissions are valid - proceeding with signing", {
        ...baseContext,
        validatedRouteCount: Object.keys(requestedMethods).length
      });
      
    } catch (error) {
      logger.errorWithContext("Failed to validate permissions - rejecting signing request", {
        ...baseContext,
        error: error.message,
        permissioned_routes: tobesignedValues.permissioned_routes
      });
      
      return res.status(400).json({
        error: "Invalid permission format",
        details: {
          message: "Could not parse requested permissions",
          parseError: error.message
        },
        requestId: req.requestId
      });
    }

    const tamperproofedValues = {
      openapijson_url: config_own_rodit.own_rodit.metadata.openapijson_url,
      not_after: tobesignedValues.not_after,
      not_before: config_own_rodit.own_rodit.metadata.not_before,
      max_requests: String(tobesignedValues.max_requests),    // Explicit conversion to string
      maxrq_window: String(tobesignedValues.maxrq_window),
      webhook_cidr: config_own_rodit.own_rodit.metadata.webhook_cidr,
      allowed_cidr: config_own_rodit.own_rodit.metadata.allowed_cidr,
      allowed_iso3166list: config_own_rodit.own_rodit.metadata.allowed_iso3166list,
      jwt_duration: config_own_rodit.own_rodit.metadata.jwt_duration,
      permissioned_routes: tobesignedValues.permissioned_routes,
      subjectuniqueidentifier_url: config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url,
      serviceprovider_id: config_own_rodit.own_rodit.metadata.serviceprovider_id,
      serviceprovider_signature: tobesignedValues.serviceprovider_signature,
    };

    // Log critical information at debug level with proper context
    const tokenContext = {
      ...baseContext,
      serviceprovider_id: tamperproofedValues.serviceprovider_id,
      not_after: tamperproofedValues.not_after,
      not_before: tamperproofedValues.not_before,
      mintingfee,
      mintingfeeaccount
    };
    
    logger.debugWithContext("Prepared tamperproofed values for signing", tokenContext);
    
    // Sign token using SignPortal
    logger.infoWithContext("Sending request to SignPortal", {
      ...baseContext,
      operation: "signPortalRodit"
    });
    
    const signResult = await signPortalRodit(
      portalPort,
      tamperproofedValues,
      mintingfee,
      mintingfeeaccount,
      roditClient
    );

    if (!signResult) {
      logger.errorWithContext("Sign operation failed with null result", baseContext);
      throw new Error("Sign operation failed");
    }

    // Success response
    const duration = Date.now() - startTime;
    const successContext = {
      ...baseContext,
      token_id: signResult.token_id,
      status: "success",
      duration,
      has_fee_signature: !!signResult.fee_signature_base64url
    };
    
    logger.infoWithContext("Successfully created new RODiT token", successContext);
    
    // Log fee signature information
    if (signResult.fee_signature_base64url) {
      logger.debugWithContext("Fee signature received from SignPortal", {
        ...baseContext,
        token_id: signResult.token_id,
        fee_signature_length: signResult.fee_signature_base64url.length
      });
    } else {
      logger.warnWithContext("No fee signature received from SignPortal", {
        ...baseContext,
        token_id: signResult.token_id
      });
    }
    
    // Add metric for successful operation
    logger.metric("signclient_operations", duration, {
      operation: "handleSignClientRequest",
      result: "success"
    });

    res.status(201).json(signResult);
  } catch (error) {
    const duration = Date.now() - startTime;
    
    // Extract the root cause from the error chain
    const rootCause = error.cause ? error.cause.message : error.message;
    const errorType = error.name || error.constructor.name;
    
    // Enhanced error logging with clear cause and effect
    logErrorWithMetrics(
      `Error in signclient endpoint: ${errorType}`,
      {
        ...baseContext,
        errorMessage: error.message,
        errorName: errorType,
        rootCause,
        reason: error.reason || "Request processing failed",
        impact: "Client request cannot be completed",
        duration
      },
      error,
      "signclient_error",
      {
        operation: "handleSignClientRequest",
        result: "error",
        duration
      }
    );

    // Return a structured error response
    res.status(500).json({
      error: "Failed to sign client request",
      reason: errorType,
      details: error.message,
      impact: "Unable to complete the requested operation",
      requestId,
    });
  }
});

module.exports = router;