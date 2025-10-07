/*
 * MCP HTTP transport integration for the main Express API.
 * Exports a single function `setupMcpHttpTransport(app)` which mounts the
 * Streamable HTTP transport at `/mcp` and registers a minimal set of tools
 * backed by the existing mcpService implementation.
 */

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const mcpService = require('../../sdk/services/mcpservice');
const logger = require('../../sdk/services/logger');

/**
 * Mounts the MCP Streamable HTTP transport on the provided Express `app`.
 * @param {import('express').Express} app
 */
async function setupMcpHttpTransport(app) {
  const mcpServer = new McpServer({
    name: 'Discernible.io MCP',
    version: '1.0.0',
    instructions: 'Use these tools via MCP streamable HTTP transport.'
  });

  // list_resources tool
  mcpServer.tool(
    'list_resources',
    'Lists available resources',
    {
      limit: z.number().optional().describe('Maximum number of resources to return'),
      cursor: z.string().optional().describe('Pagination cursor')
    },
    async ({ limit, cursor }, ctx) => {
      const result = await mcpService.listAvailableResources(ctx?.request ?? { user: {} }, { limit, cursor });
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    }
  );

  // get_resource tool
  mcpServer.tool(
    'get_resource',
    'Retrieves a specific resource by URI',
    {
      uri: z.string().describe('Resource URI (e.g. "health/info")')
    },
    async ({ uri }, ctx) => {
      const result = await mcpService.getResource(uri, ctx?.request ?? { user: {} });
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    }
  );

  // Additional tools from mcpService can be exposed here as needed.

    // According to SDK ≥1.12 the transport itself is an Express router.
  const transport = new StreamableHTTPServerTransport({ server: mcpServer });
  // Initialize transport
  await mcpServer.connect(transport);
  // Determine a function/Router that Express can use
  let handler;
  let handlerType = 'unknown';
  if (typeof transport.expressMiddleware === 'function') {
    handlerType = 'expressMiddleware';
    handler = transport.expressMiddleware();
  } else if (typeof transport.handleRequest === 'function') {
    handlerType = 'handleRequestWrapper';
    handler = (req, res) => transport.handleRequest(req, res);
  } else {
    // log available keys for debugging
    logger.error(`[MCP] Unsupported transport shape. Keys: ${Object.keys(transport).join(', ')}`);
    throw new TypeError('Unsupported transport shape for Express mounting');
  }

  logger.info(`[MCP] Mounted StreamableHTTPServerTransport using handler type: ${handlerType}`);
  // Mount on both legacy /api/mcp and new /mcp for compatibility
  app.use('/mcp', handler);
  app.use('/api/mcp', handler);
}

module.exports = { setupMcpHttpTransport };
