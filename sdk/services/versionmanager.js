/**
 * Version Manager for RODiT SDK
 * 
 * Handles API versioning for client-side requests, ensuring proper version headers
 * are included in all API calls.
 * 
 * Copyright (c) 2025 Discernible Inc. All rights reserved.
 */

const config = require('./configsdk');

/**
 * Version Manager class for handling API versioning in client requests
 */
class VersionManager {
  /**
   * Create a new VersionManager instance
   * @param {Object} versioning - Configuration versioning
   * @param {string} [versioning.version] - API version to use
   */
  constructor(versioning = {}) {
    this.version = versioning.version || config.get('API_VERSION');
  }

  /**
   * Set the API version to use for requests
   * @param {string} version - API version in format X.Y.Z
   * @returns {VersionManager} This instance for chaining
   */
  setVersion(version) {
    if (!version || typeof version !== 'string') {
      throw new Error('Version must be a valid string in format X.Y.Z');
    }
    
    // Validate version format
    if (!version.match(/^\d+\.\d+\.\d+$/)) {
      throw new Error('Version must be in format X.Y.Z (e.g., 1.0.0)');
    }
    
    this.version = version;
    return this;
  }


  /**
   * Apply version headers to a request versioning object
   * @param {Object} versioning - Request versioning object (e.g., for fetch or axios)
   * @returns {Object} Updated versioning with version headers
   */
  applyVersionHeaders(versioning = {}) {
    if (!versioning.headers) {
      versioning.headers = {};
    }
    
    // Always apply version header
    versioning.headers['X-API-Version'] = this.version;
    
    return versioning;
  }

  /**
   * Create a headers object with version headers
   * @returns {Object} Headers object with version headers
   */
  getVersionHeaders() {
    const headers = {};
    
    // Always include version header
    headers['X-API-Version'] = this.version;
    
    return headers;
  }
}

// Create a singleton instance
const versionManager = new VersionManager();

module.exports = {
  VersionManager,
  versionManager
};
