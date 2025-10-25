#!/usr/bin/env node
/**
 * Generate METHOD_PERMISSION_MAP from swagger.json
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 * 
 * This script reads the OpenAPI/Swagger specification and generates
 * the METHOD_PERMISSION_MAP configuration automatically.
 * 
 * Usage:
 *   node scripts/generate-permission-map.js
 *   node scripts/generate-permission-map.js --output config/default.json
 *   node scripts/generate-permission-map.js --validate
 */

const fs = require('fs');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);
const validateOnly = args.includes('--validate');
const outputIndex = args.indexOf('--output');
const outputPath = outputIndex !== -1 ? args[outputIndex + 1] : null;

// Paths
const SWAGGER_PATH = path.join(__dirname, '../api-docs/swagger.json');
const DEFAULT_CONFIG_PATH = path.join(__dirname, '../config/default.json');

/**
 * Extract operation name from a path
 * @param {string} path - API path (e.g., "/timezone/time")
 * @returns {string|null} - Operation name (e.g., "time") or null
 */
function extractOperationName(path) {
  // Remove leading/trailing slashes and split
  const segments = path.split('/').filter(s => s && !s.startsWith('{'));
  
  if (segments.length === 0) {
    return null;
  }
  
  // Return the last segment as the operation name
  return segments[segments.length - 1];
}

/**
 * Check if a path item requires authentication
 * @param {object} pathItem - OpenAPI path item object
 * @returns {boolean}
 */
function requiresAuthentication(pathItem) {
  const methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];
  
  for (const method of methods) {
    if (pathItem[method]) {
      const operation = pathItem[method];
      // Check if security is defined and not empty
      if (operation.security && operation.security.length > 0) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Get custom permission scopes from OpenAPI extension
 * @param {object} pathItem - OpenAPI path item object
 * @returns {string[]|null} - Custom permission scopes or null for default
 */
function getCustomPermissionScopes(pathItem) {
  const methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];
  
  for (const method of methods) {
    if (pathItem[method]) {
      const operation = pathItem[method];
      // Check for custom extension
      if (operation['x-permission-scopes']) {
        return operation['x-permission-scopes'];
      }
    }
  }
  
  return null;
}

/**
 * Generate METHOD_PERMISSION_MAP from swagger specification
 * @param {object} swaggerSpec - Parsed swagger.json
 * @returns {object} - Generated permission map
 */
function generatePermissionMap(swaggerSpec) {
  const permissionMap = {};
  const paths = swaggerSpec.paths || {};
  
  console.log('Generating METHOD_PERMISSION_MAP from swagger.json...\n');
  
  for (const [pathStr, pathItem] of Object.entries(paths)) {
    const operation = extractOperationName(pathStr);
    
    if (!operation) {
      console.log(`⚠️  Skipping path without operation name: ${pathStr}`);
      continue;
    }
    
    const requiresAuth = requiresAuthentication(pathItem);
    
    if (!requiresAuth) {
      console.log(`ℹ️  Skipping unauthenticated endpoint: ${pathStr} (${operation})`);
      continue;
    }
    
    // Get custom scopes or use default
    const customScopes = getCustomPermissionScopes(pathItem);
    const scopes = customScopes || ["entityAndProperties", "propertiesOnly", "entityOnly"];
    
    // Check for duplicates
    if (permissionMap[operation]) {
      console.log(`⚠️  Duplicate operation name detected: ${operation}`);
      console.log(`    Existing: ${JSON.stringify(permissionMap[operation])}`);
      console.log(`    New from ${pathStr}: ${JSON.stringify(scopes)}`);
      console.log(`    Keeping existing definition.`);
    } else {
      permissionMap[operation] = scopes;
      console.log(`✓ ${operation.padEnd(20)} <- ${pathStr}`);
    }
  }
  
  console.log(`\n✓ Generated ${Object.keys(permissionMap).length} permission entries`);
  
  return permissionMap;
}

/**
 * Validate that generated map matches existing config
 * @param {object} generated - Generated permission map
 * @param {object} existing - Existing permission map from config
 * @returns {boolean} - True if they match
 */
function validatePermissionMap(generated, existing) {
  console.log('\n=== Validation Report ===\n');
  
  let isValid = true;
  const generatedKeys = new Set(Object.keys(generated));
  const existingKeys = new Set(Object.keys(existing));
  
  // Check for missing operations in generated map
  const missingInGenerated = [...existingKeys].filter(k => !generatedKeys.has(k));
  if (missingInGenerated.length > 0) {
    console.log('❌ Operations in config but NOT in swagger.json:');
    missingInGenerated.forEach(op => {
      console.log(`   - ${op}: ${JSON.stringify(existing[op])}`);
    });
    isValid = false;
  }
  
  // Check for new operations in generated map
  const newInGenerated = [...generatedKeys].filter(k => !existingKeys.has(k));
  if (newInGenerated.length > 0) {
    console.log('ℹ️  New operations found in swagger.json:');
    newInGenerated.forEach(op => {
      console.log(`   + ${op}: ${JSON.stringify(generated[op])}`);
    });
  }
  
  // Check for differences in existing operations
  const commonKeys = [...generatedKeys].filter(k => existingKeys.has(k));
  const differences = [];
  
  for (const key of commonKeys) {
    const genScopes = JSON.stringify(generated[key].sort());
    const existScopes = JSON.stringify(existing[key].sort());
    
    if (genScopes !== existScopes) {
      differences.push({
        operation: key,
        generated: generated[key],
        existing: existing[key]
      });
    }
  }
  
  if (differences.length > 0) {
    console.log('\n⚠️  Operations with different permission scopes:');
    differences.forEach(diff => {
      console.log(`   ${diff.operation}:`);
      console.log(`     Config:    ${JSON.stringify(diff.existing)}`);
      console.log(`     Generated: ${JSON.stringify(diff.generated)}`);
    });
    isValid = false;
  }
  
  if (isValid && missingInGenerated.length === 0 && newInGenerated.length === 0) {
    console.log('✓ Generated map matches existing config perfectly!');
  } else if (isValid) {
    console.log('\n✓ Existing operations match, but there are new operations to add.');
  }
  
  return isValid;
}

/**
 * Update config file with new permission map
 * @param {string} configPath - Path to config file
 * @param {object} permissionMap - New permission map
 */
function updateConfigFile(configPath, permissionMap) {
  console.log(`\nUpdating ${configPath}...`);
  
  let config;
  try {
    const configContent = fs.readFileSync(configPath, 'utf8');
    config = JSON.parse(configContent);
  } catch (error) {
    console.error(`❌ Failed to read config file: ${error.message}`);
    process.exit(1);
  }
  
  // Update the METHOD_PERMISSION_MAP
  config.METHOD_PERMISSION_MAP = permissionMap;
  
  // Write back with pretty formatting
  try {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
    console.log('✓ Config file updated successfully!');
  } catch (error) {
    console.error(`❌ Failed to write config file: ${error.message}`);
    process.exit(1);
  }
}

// Main execution
function main() {
  console.log('=== METHOD_PERMISSION_MAP Generator ===\n');
  
  // Read swagger.json
  let swaggerSpec;
  try {
    const swaggerContent = fs.readFileSync(SWAGGER_PATH, 'utf8');
    swaggerSpec = JSON.parse(swaggerContent);
    console.log(`✓ Loaded swagger.json from ${SWAGGER_PATH}\n`);
  } catch (error) {
    console.error(`❌ Failed to read swagger.json: ${error.message}`);
    process.exit(1);
  }
  
  // Generate permission map
  const generatedMap = generatePermissionMap(swaggerSpec);
  
  if (validateOnly) {
    // Validation mode
    let existingConfig;
    try {
      const configContent = fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8');
      existingConfig = JSON.parse(configContent);
    } catch (error) {
      console.error(`❌ Failed to read config file: ${error.message}`);
      process.exit(1);
    }
    
    const isValid = validatePermissionMap(generatedMap, existingConfig.METHOD_PERMISSION_MAP || {});
    process.exit(isValid ? 0 : 1);
  } else {
    // Update mode
    const targetPath = outputPath || DEFAULT_CONFIG_PATH;
    updateConfigFile(targetPath, generatedMap);
    
    console.log('\n=== Summary ===');
    console.log(`Total operations: ${Object.keys(generatedMap).length}`);
    console.log('Default scopes: ["entityAndProperties", "propertiesOnly", "entityOnly"]');
    console.log('\nTo customize permission scopes for specific operations,');
    console.log('add "x-permission-scopes" to the operation in swagger.json:');
    console.log('\nExample:');
    console.log('  "/admin/endpoint": {');
    console.log('    "post": {');
    console.log('      "summary": "Admin only endpoint",');
    console.log('      "x-permission-scopes": ["entityAndProperties"],');
    console.log('      "security": [{ "bearerAuth": [] }]');
    console.log('    }');
    console.log('  }');
  }
}

// Run the script
main();
