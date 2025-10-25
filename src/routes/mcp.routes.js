/**
 * Model Context Protocol (MCP) Routes
 * 
 * This file defines routes that implement the Model Context Protocol (MCP) interface,
 * allowing AI models to access structured data from the application.
 */

const config = require('config');
const express = require('express');
const router = express.Router();
const { ulid } = require('ulid');
const { logger } = require('@rodit/rodit-auth-be');

// Authentication middleware - uses app.locals.roditClient
const authenticate_apicall = (req, res, next) => {
  const client = req.app?.locals?.roditClient;
  if (!client) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
  return client.authenticate(req, res, next);
};

const { createLogContext, logErrorWithMetrics } = logger;

// Minimal local MCP service implementation to satisfy tests
// Provides resources list, resource retrieval, and schema retrieval
const mcpCache = {
  swagger: null
};

function loadSwaggerSpec() {
  if (mcpCache.swagger) return mcpCache.swagger;
  try {
    // Load swagger spec from require (already parsed JSON)
    mcpCache.swagger = require('../../api-docs/swagger.json');
    return mcpCache.swagger;
  } catch (error) {
    logger.error('Failed to load swagger.json for MCP schema', {
      component: 'MCPRoutes',
      method: 'loadSwaggerSpec',
      error: error.message
    });
    // Return a minimal valid OpenAPI object as fallback
    mcpCache.swagger = {
      openapi: '3.0.0',
      info: { title: 'Time Here Now API', version: '1.0.0' },
      paths: {}
    };
    return mcpCache.swagger;
  }
}

const mcpService = {
  async listAvailableResources(req, options = {}) {
    const all = [
      { uri: 'openapi:swagger', name: 'OpenAPI Schema', type: 'application/json' },
      { uri: 'config:default', name: 'Server Default Config', type: 'application/json' },
      { uri: 'readme:main', name: 'README Documentation', type: 'text/markdown' },
      { uri: 'health:status', name: 'Health Status with NEAR Blockchain Info', type: 'application/json' },
      { uri: 'guide:api', name: 'Comprehensive API Guide', type: 'application/json' }
    ];
    const start = options.cursor ? parseInt(options.cursor, 10) || 0 : 0;
    const limit = options.limit || all.length;
    const resources = all.slice(start, start + limit);
    const nextCursor = start + limit < all.length ? String(start + limit) : null;
    return { resources, nextCursor };
  },

  async getResource(uri, req) {
    if (uri === 'openapi:swagger') {
      return { type: 'application/json', content: loadSwaggerSpec() };
    }
    if (uri === 'config:default') {
      try {
        // Use config.get() to access configuration properly
        const configData = {
          RATE_LIMITING: config.has('RATE_LIMITING') ? config.get('RATE_LIMITING') : null,
          METHOD_PERMISSION_MAP: config.has('METHOD_PERMISSION_MAP') ? config.get('METHOD_PERMISSION_MAP') : null,
          SERVERPORT: config.has('SERVERPORT') ? config.get('SERVERPORT') : null,
          SERVICE_NAME: config.has('SERVICE_NAME') ? config.get('SERVICE_NAME') : null,
          NODE_ENV: config.has('NODE_ENV') ? config.get('NODE_ENV') : null
        };
        return { type: 'application/json', content: configData };
      } catch (error) {
        logger.error('Failed to load config for MCP resource', {
          component: 'MCPRoutes',
          method: 'getResource',
          uri,
          error: error.message
        });
        throw new Error('Resource unavailable');
      }
    }
    if (uri === 'readme:main') {
      try {
        // Get README content from RODiT configuration if available
        const roditClient = req.app?.locals?.roditClient;
        if (!roditClient) {
          throw new Error('RoditClient not available');
        }
        
        const config_own_rodit = await roditClient.getConfigOwnRodit();
        if (!config_own_rodit?.own_rodit?.metadata?.openapijson_url) {
          throw new Error('RODiT configuration not available');
        }
        
        // Return a summary instead of full README
        const readmeSummary = {
          title: 'Time Here Now API',
          description: 'API to get the current time based on timezone or client IP using NEAR blockchain time',
          documentation_url: config_own_rodit.own_rodit.metadata.openapijson_url,
          purchase_url: 'https://purchase.timeherenow.com',
          key_features: [
            'Blockchain time from NEAR (not system/NTP time)',
            '5 Hz polling for low-latency access',
            'Timezone data from IANA tzdb',
            'IP-based geolocation',
            'Delayed webhooks with blockchain timestamps',
            'RODiT authentication'
          ]
        };
        return { type: 'application/json', content: readmeSummary };
      } catch (error) {
        logger.error('Failed to load README for MCP resource', {
          component: 'MCPRoutes',
          method: 'getResource',
          uri,
          error: error.message
        });
        throw new Error('Resource unavailable');
      }
    }
    if (uri === 'health:status') {
      try {
        // Fetch health status from the health endpoint
        const axios = require('axios');
        
        // Get base URL from RODiT configuration instead of config file
        const roditClient = req.app?.locals?.roditClient;
        if (!roditClient) {
          throw new Error('RoditClient not available');
        }
        
        const config_own_rodit = await roditClient.getConfigOwnRodit();
        if (!config_own_rodit?.own_rodit?.metadata?.subjectuniqueidentifier_url) {
          throw new Error('RODiT configuration not available');
        }
        
        const baseUrl = config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url;
        const response = await axios.get(`${baseUrl}/health`, { timeout: 5000 });
        return { type: 'application/json', content: response.data };
      } catch (error) {
        logger.error('Failed to fetch health status for MCP resource', {
          component: 'MCPRoutes',
          method: 'getResource',
          uri,
          error: error.message
        });
        throw new Error('Health status unavailable');
      }
    }
    if (uri === 'guide:api') {
      try {
        // Create comprehensive API guide from configuration and swagger
        const swagger = loadSwaggerSpec();
        const roditClient = req.app?.locals?.roditClient;
        
        // Get base URL from RODiT configuration
        let baseUrl = swagger.servers?.[0]?.url;
        if (roditClient) {
          const config_own_rodit = await roditClient.getConfigOwnRodit();
          if (config_own_rodit?.own_rodit?.metadata?.subjectuniqueidentifier_url) {
            baseUrl = config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url;
          }
        }
        
        const guide = {
          title: 'Time Here Now API - Comprehensive Guide',
          version: swagger.info?.version || '1.0.0',
          description: 'Complete API documentation combining README context with OpenAPI specifications',
          sections: {
            overview: {
              description: 'Time Here Now API provides blockchain-based time services using NEAR Protocol',
              key_features: [
                'Blockchain time from NEAR (not system/NTP time)',
                '5 Hz polling for low-latency access',
                'Timezone data from IANA tzdb',
                'IP-based geolocation',
                'Delayed webhooks with blockchain timestamps',
                'RODiT authentication'
              ]
            },
            blockchain_time: {
              description: 'All time endpoints use NEAR blockchain time instead of system time',
              polling: {
                frequency: '5 Hz (200ms intervals)',
                cache_ttl: '1 second',
                block_interval: '~600ms',
                network_margin: '50ms'
              },
              accuracy: {
                field: 'likely_time_difference_ms',
                description: 'Conservative >99% likely upper-bound difference between real time and returned time',
                calculation: 'max(observed_lag, block_interval + poll_interval + network_margin)'
              },
              availability: 'Returns HTTP 503 if blockchain time is unavailable'
            },
            authentication: {
              method: 'RODiT mutual authentication',
              purchase_url: 'https://purchase.timeherenow.com',
              description: 'RODiT tokens are NFTs on NEAR blockchain representing API access rights. Purchase them at https://purchase.timeherenow.com',
              flow: [
                '1. Purchase RODiT tokens at https://purchase.timeherenow.com',
                '2. Extract RODiT credentials from your NEAR wallet',
                '3. POST /api/login with roditToken',
                '4. Receive JWT token in response',
                '5. Include token in Authorization: Bearer <token> header',
                '6. POST /api/logout to terminate session'
              ]
            },
            endpoints: swagger.paths,
            schemas: swagger.components?.schemas || {}
          },
          base_url: baseUrl,
          external_docs: swagger.externalDocs
        };
        
        return { type: 'application/json', content: guide };
      } catch (error) {
        logger.error('Failed to create API guide for MCP resource', {
          component: 'MCPRoutes',
          method: 'getResource',
          uri,
          error: error.message
        });
        throw new Error('API guide unavailable');
      }
    }
    throw new Error(`Unknown resource: ${uri}`);
  },

  async getSchemaResource(req) {
    return loadSwaggerSpec();
  }
};

/**
 * @swagger
 * /api/mcp/resources:
 *   get:
 *     summary: List available MCP resources
 *     description: Returns a list of resources available through the MCP interface
 *     tags: [MCP]
 *     responses:
 *       200:
 *         description: List of available resources
 */
router.get('/resources', async (req, res) => {
  const requestId = req.requestId || ulid();
  const startTime = Date.now();
  
  const baseContext = createLogContext({
    requestId,
    component: 'MCPRoutes',
    method: 'listResources',
    endpoint: '/api/mcp/resources',
    httpMethod: req.method,
    userId: req.user?.id,
    ip: req.ip,
    limit: req.query.limit,
    hasCursor: !!req.query.cursor
  });
  
  logger.debugWithContext('Processing MCP resources list request', baseContext);
  
  try {
    // Extract pagination parameters from query
    const options = {
      limit: req.query.limit ? parseInt(req.query.limit, 10) : undefined,
      cursor: req.query.cursor
    };
    
    // Get resources with pagination
    const result = await mcpService.listAvailableResources(req, options);
    
    const duration = Date.now() - startTime;
    logger.infoWithContext('MCP resources listed successfully', {
      ...baseContext,
      resourceCount: result.resources?.length || 0,
      hasNextCursor: !!result.nextCursor,
      duration
    });
    
    // Add metric for successful operation
    logger.metric('mcp_operations', duration, {
      operation: 'listResources',
      result: 'success'
    });
    
    res.json({
      ...result,
      requestId
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logErrorWithMetrics(
      'Error listing MCP resources',
      {
        ...baseContext,
        duration
      },
      error,
      'mcp_error',
      {
        operation: 'listResources',
        result: 'error',
        duration
      }
    );
    
    res.status(500).json({
      error: 'Failed to list resources',
      message: error.message,
      requestId
    });
  }
});

/**
 * GET /api/mcp/resource/:uri
 * 
 * Get a specific MCP resource by URI
 * 
 * @swagger
 * /api/mcp/resource/{uri}:
 *   get:
 *     summary: Get a specific MCP resource
 *     description: Retrieves the content of a specific resource by its URI (Public for AI discovery)
 *     tags:
 *       - MCP
 *     parameters:
 *       - in: path
 *         name: uri
 *         required: true
 *         schema:
 *           type: string
 *         description: The URI of the resource to retrieve
 *     responses:
 *       200:
 *         description: Resource content
 *       404:
 *         description: Resource not found
 */
router.get('/resource/:uri(*)', async (req, res) => {
  const requestId = req.requestId || ulid();
  const startTime = Date.now();
  const uri = req.params.uri;
  
  const baseContext = createLogContext({
    requestId,
    component: 'MCPRoutes',
    method: 'getResource',
    endpoint: '/api/mcp/resource/:uri',
    httpMethod: req.method,
    userId: req.user?.id,
    ip: req.ip,
    resourceUri: uri
  });
  
  logger.debugWithContext('Processing MCP resource request', baseContext);
  
  try {
    const resource = await mcpService.getResource(uri, req);
    
    if (!resource) {
      logger.warnWithContext('MCP resource not found', {
        ...baseContext,
        status: 404
      });
      
      return res.status(404).json({
        error: 'Resource not found',
        uri,
        requestId
      });
    }
    
    const duration = Date.now() - startTime;
    logger.infoWithContext('MCP resource retrieved successfully', {
      ...baseContext,
      resourceType: resource.type || 'unknown',
      resourceSize: JSON.stringify(resource).length,
      duration
    });
    
    // Add metric for successful operation
    logger.metric('mcp_operations', duration, {
      operation: 'getResource',
      resourceUri: uri,
      result: 'success'
    });
    
    res.json({
      ...resource,
      requestId
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    const errorContext = {
      ...baseContext,
      duration,
      errorMessage: error.message
    };
    
    if (error.message.includes('Unauthorized')) {
      logger.warnWithContext('Unauthorized access to MCP resource', errorContext);
      
      // Add metric for unauthorized access
      logger.metric('mcp_operations', duration, {
        operation: 'getResource',
        resourceUri: uri,
        result: 'unauthorized'
      });
      
      return res.status(401).json({
        error: 'Unauthorized access to resource',
        message: error.message,
        requestId
      });
    }
    
    if (error.message.includes('Unknown') || error.message.includes('not found')) {
      logger.warnWithContext('MCP resource not found', errorContext);
      
      // Add metric for not found
      logger.metric('mcp_operations', duration, {
        operation: 'getResource',
        resourceUri: uri,
        result: 'not_found'
      });
      
      return res.status(404).json({
        error: 'Resource not found',
        message: error.message,
        requestId
      });
    }
    
    logErrorWithMetrics(
      'Error retrieving MCP resource',
      errorContext,
      error,
      'mcp_error',
      {
        operation: 'getResource',
        resourceUri: uri,
        result: 'error',
        duration
      }
    );
    
    res.status(500).json({
      error: 'Failed to retrieve resource',
      message: error.message,
      requestId
    });
  }
});

/**
 * GET /api/mcp/schema
 * 
 * Get the MCP OpenAPI schema
 * 
 * @swagger
 * /api/mcp/schema:
 *   get:
 *     summary: Get MCP OpenAPI schema
 *     description: Returns the OpenAPI schema for the MCP interface (Public for AI discovery)
 *     tags:
 *       - MCP
 *     responses:
 *       200:
 *         description: MCP schema
 */
router.get('/schema', async (req, res) => {
  const requestId = req.requestId || ulid();
  const startTime = Date.now();
  
  const baseContext = createLogContext({
    requestId,
    component: 'MCPRoutes',
    method: 'getSchema',
    endpoint: '/api/mcp/schema',
    httpMethod: req.method,
    userId: req.user?.id,
    ip: req.ip
  });
  
  logger.debugWithContext('Processing MCP schema request', baseContext);
  
  try {
    // Reuse the schema resource to avoid duplication
    const schema = await mcpService.getSchemaResource(req);
    
    const duration = Date.now() - startTime;
    logger.infoWithContext('MCP schema retrieved successfully', {
      ...baseContext,
      schemaSize: JSON.stringify(schema).length,
      duration
    });
    
    // Add metric for successful operation
    logger.metric('mcp_operations', duration, {
      operation: 'getSchema',
      result: 'success'
    });
    
    res.json({
      ...schema,
      requestId
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logErrorWithMetrics(
      'Error retrieving MCP schema',
      {
        ...baseContext,
        duration
      },
      error,
      'mcp_error',
      {
        operation: 'getSchema',
        result: 'error',
        duration
      }
    );
    
    res.status(500).json({
      error: 'Failed to retrieve schema',
      message: error.message,
      requestId
    });
  }
});

module.exports = router;
module.exports.mcpService = mcpService;
