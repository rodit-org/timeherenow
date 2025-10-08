/**
 * File-based credential storage system
 * Alternative to Vault for storing RODiT credentials
 * 
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const fs = require('fs').promises;
const { ulid } = require("ulid");
const config = require('../../services/configsdk');
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const { validateAndExtractCredentials } = require("../../services/utils");
class FileManager {
  constructor() {
    this.credentialsFilePath = config.get("NEAR_CREDENTIALS_FILE_PATH");
    this.initialized = false;
    this.credentials = {};
  }

  async initialize(source = {}) {
    const context = createLogContext("FileCredentialStore", "initialize", {
      requestId: ulid(),
      hasConfigPath: !!source.credentialsFilePath
    });
  
    logger.debugWithContext("Initializing file credential store", context);
  
    if (this.initialized) {
      logger.debugWithContext("File credential store already initialized", context);
      return this;
    }
  
    try {
      this.credentialsFilePath = source.credentialsFilePath || config.get('NEAR_CREDENTIALS_FILE_PATH');
      if (!this.credentialsFilePath) {
        throw new Error('NEAR_CREDENTIALS_FILE_PATH is not set in config or source');
      }
  
      // Ensure the directory exists
      try {
        await fs.mkdir(require('path').dirname(this.credentialsFilePath), { recursive: true });
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
      }

      const credentials = await this.getCredentials();
      this.credentials = credentials || {}; // Ensure we always have an object
      this.initialized = true;
      
      logger.debugWithContext("File credential store initialized successfully", {
        ...context,
        credentialsFilePath: this.credentialsFilePath,
        credentialCount: this.credentials ? Object.keys(this.credentials).length : 0
      });
  
      return this;
    } catch (error) {
      logger.errorWithContext("Failed to initialize file credential store", {
        ...context,
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  async checkReadFileAccess(filePath) {
    try {
      const stats = await fs.stat(filePath);
      await fs.access(filePath, fs.constants.R_OK);
      return { exists: true, isReadable: true, stats };
    } catch (error) {
      if (error.code === 'ENOENT') {
        return { exists: false, isReadable: false };
      }
      return { 
        exists: false, 
        isReadable: false, 
        error: error.message,
        code: error.code
      };
    }
  }

  async getCredentials(source) {
    const context = createLogContext("FileCredentialStore", "getCredentials", {
      requestId: ulid(),
      source: source || 'all'
    });
    const startTime = Date.now();
    let result = {};

    try {
      // Check file access and read content
      const { exists } = await this.checkReadFileAccess(this.credentialsFilePath);
      if (!exists) {
        logger.infoWithContext("Credentials file does not exist", { ...context, credentialsFilePath: this.credentialsFilePath });
        return result;
      }

      // Read and parse file content
      const fileContent = await fs.readFile(this.credentialsFilePath, 'utf8');
      if (!fileContent.trim()) {
        logger.infoWithContext("Credentials file is empty", { ...context, credentialsFilePath: this.credentialsFilePath });
        return result;
      }

      // Parse and validate credentials using the utility function
      result = validateAndExtractCredentials(JSON.parse(fileContent), logger);

      logger.debugWithContext("Successfully processed credentials", {
        ...context,
        hasRequiredFields: true,
        duration: Date.now() - startTime
      });

      return result;
    } catch (error) {
      logErrorWithMetrics(
        "Error retrieving credentials from file",
        {
          ...context,
          duration: Date.now() - startTime,
          errorDetails: error.message,
          errorType: error.name,
          credentialsFilePath: this.credentialsFilePath,
          stack: error.stack
        },
        error,
        error.name === 'SyntaxError' ? "file_parse_error" : "file_credential_retrieval_error",
        { error_type: error.name === 'SyntaxError' ? "parse_failure" : "retrieval_failure" }
      );
      throw error;
    }
  }

  // Mock function to maintain interface compatibility with vaultcredentialstore.js
  async setupTokenRenewal(store) {
    const context = createLogContext("FileCredentialStore", "setupTokenRenewal", {
      requestId: ulid()
    });
    logger.debugWithContext("Skipping token renewal setup (not applicable for file-based credentials)", context);
    return Promise.resolve();
  }
}

// Create and export a singleton instance
const fileManager = new FileManager();

module.exports = {
  initializeProductionCredentialStore: (source) => fileManager.initialize(source),
  setupTokenRenewal: () => fileManager.setupTokenRenewal(),
  getCredentials: (source) => fileManager.getCredentials(source),
  vault: null,
  // For testing purposes
  _fileManager: fileManager
};
