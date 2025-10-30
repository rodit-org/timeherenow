/**
 * API Versioning Middleware
 * 
 * This middleware handles API versioning through HTTP headers.
 * It supports both client request versioning and server response versioning.
 * 
 * Copyright (c) 2025 Discernible Inc. All rights reserved.
 */

const logger = require('../../services/logger');
const config = require('../../services/configsdk');



/**
 * Parse version from header value
 * @param {string} headerValue - Value from Accept or X-API-Version header
 * @returns {string} Parsed version or default version
 */
function parseVersionFromHeader(headerValue) {
  if (!headerValue) return config.get('API_VERSION');
  
  // Handle Accept header format: application/vnd.company.vX+json
  const vendorMatch = headerValue.match(/application\/vnd\.rodit\.v([0-9.]+)\+json/i);
  if (vendorMatch && vendorMatch[1]) {
    return vendorMatch[1];
  }
  
  // Handle X-API-Version header format: X.Y.Z
  const versionMatch = headerValue.match(/([0-9]+\.[0-9]+\.[0-9]+)/);
  if (versionMatch && versionMatch[1]) {
    return versionMatch[1];
  }
  
  return config.get('API_VERSION');
}

/**
 * Check if requested version is supported
 * @param {string} version - Requested version
 * @returns {boolean} True if version is supported
 */
function isVersionSupported(version) {
  return AVAILABLE_VERSIONS.includes(version);
}

/**
 * Check if version is deprecated
 * @param {string} version - API version
 * @returns {boolean} True if version is deprecated
 */
function isVersionDeprecated(version) {
  return DEPRECATED_VERSIONS.includes(version);
}

/**
 * Get major version number from version string
 * @param {string} version - Version string (e.g., "1.2.3")
 * @returns {number} Major version number
 */
function getMajorVersion(version) {
  const parts = version.split('.');
  return parseInt(parts[0], 10);
}

/**
 * Middleware to handle API versioning
 * @param {Object} versioning - Configuration versioning
 * @param {boolean} [versioning.strict=false] - If true, reject requests with unsupported versions
 * @returns {Function} Express middleware
 */
function versioningMiddleware(versioning = {}) {
  const strict = versioning.strict || false;
  
  return (req, res, next) => {
    const requestId = req.headers['x-request-id'] || 'unknown';
    const logContext = { component: 'versioningMiddleware', requestId };
    logger.infoWithContext('API versioning middleware engaged', {
      ...logContext,
      result: 'call',
      reason: 'Versioning middleware called'
    });
    
    // Check for version in headers (multiple possible formats)
    const acceptHeader = req.headers['accept'];
    const versionHeader = req.headers['x-api-version'];
    
    // Parse version from headers
    let requestedVersion = parseVersionFromHeader(versionHeader || acceptHeader);
    
    // Check if version is supported
    if (!isVersionSupported(requestedVersion)) {
      logger.warnWithContext('Unsupported API version requested', {
        ...logContext,
        version: requestedVersion,
        result: 'failure',
        reason: `API version ${requestedVersion} is not supported.`
      });
      
      if (strict) {
        return res.status(400).json({
          error: 'unsupported_version',
          message: `API version ${requestedVersion} is not supported. Supported versions: ${AVAILABLE_VERSIONS.join(', ')}`,
          supportedVersions: AVAILABLE_VERSIONS
        });
      }
      requestedVersion = config.get('API_VERSION');
    }
    
    // Add version info to request object for use in route handlers
    req.apiVersion = requestedVersion;
    req.apiMajorVersion = getMajorVersion(requestedVersion);
    
    // Add deprecation warning header if applicable
    if (isVersionDeprecated(requestedVersion)) {
      res.setHeader('Warning', `299 - "Deprecated API version ${requestedVersion}. Please upgrade to a newer version."`);
      res.setHeader('X-API-Deprecated', 'true');
      res.setHeader('X-API-Deprecated-Message', `Version ${requestedVersion} is deprecated and will be removed in the future.`);
    }
    
    // Set response version header
    res.setHeader('X-API-Version', requestedVersion);
    
    logger.infoWithContext('API request using version', {
      ...logContext,
      version: requestedVersion,
      result: 'success',
      reason: `API request using version ${requestedVersion}`
    });
    next();
  };
}

module.exports = {
  versioningMiddleware,
  parseVersionFromHeader,
  isVersionSupported,
  isVersionDeprecated
};
