#!/usr/bin/env node

import express, { Request, Response, NextFunction } from 'express';
import { ScimService, ScimApiError } from './services/scimService.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from "zod";
import dotenv from 'dotenv';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { CreateMessageResultSchema } from '@modelcontextprotocol/sdk/types.js';

// Load environment variables from .env file
dotenv.config();

// Configuration
const config = {
  port: process.env.PORT || 3000,
  scimUrl: process.env.SCIM_URL || 'http://localhost:8080',
  isDevelopment: process.env.NODE_ENV === 'development',
  mode: process.env.MCP_MODE || (process.argv.includes('--stdio') ? 'stdio' : 'http')
};

const ElicitResultSchema = z.object({
  action: z.enum(['accept', 'decline', 'cancel']),
  content: z.record(z.union([z.string(), z.number(), z.boolean()])).optional()
}).passthrough();

/**
 * Extract token from authorization header by removing 'Bearer ' prefix if present
 */
function extractToken(authHeader?: string): string | undefined {
  if (!authHeader) return undefined;
  
  // If it starts with 'Bearer ', remove that prefix
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7); // 'Bearer '.length === 7
  }
  
  // Otherwise return the header as is
  return authHeader;
}

/**
 * Wrapper function for tool handlers with standardized error handling
 */
function withErrorHandling<T, R>(handler: (params: T, extra: R) => Promise<any>) {
  return async (params: T, extra: R) => {
    try {
      return await handler(params, extra);
    } catch (error) {
      if (error instanceof ScimApiError) {
        return {
          content: [
            {
              type: "text",
              text: `Error (${error.statusCode}): ${error.message}\n\nResponse Body:\n${JSON.stringify(error.responseBody, null, 2)}`
            }
          ]
        };
      }
      // For other types of errors
      console.error('Unhandled error in tool:', error);
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : 'Unknown error occurred'}`
          }
        ]
      };
    }
  };
}

function getServer(authHeader?: string) {
  // Extract the token from the authorization header
  const authToken = extractToken(authHeader);
  
  // Create a new ScimService instance with the auth token from the request
  const scimService = new ScimService(config.scimUrl, authToken);
  
  const server = new McpServer({
    name: "scim-server",
    version: "0.0.1"
  });

  // Retrieve SCIM Resource Types
  server.tool('resourcetypes', 'Retrieve available SCIM resource types. Use this before creating resources to understand available resource types and schemas.', {}, withErrorHandling(async (_, extra) => {
    const resourceTypes = await scimService.getResourceTypes();
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(resourceTypes, null, 2)
        }
      ]
    };
  }));

  server.tool('getResources', 'Retrieve resources from SCIM server according to RFC 7644', {
    resourceType: z.string().describe('Type of resource to retrieve (e.g., Users, Groups, etc.)'),
    filter: z.string().optional().describe('SCIM filter query parameter'),
    startIndex: z.number().positive().optional().describe('1-based index of the first query result'),
    count: z.number().positive().optional().describe('Non-negative integer specifying the desired max resource count'),
    attributes: z.string().optional().describe('Comma-separated list of attribute names to return'),
    excludedAttributes: z.string().optional().describe('Comma-separated list of attribute names to exclude'),
    sortBy: z.string().optional().describe('Attribute name to sort by'),
    sortOrder: z.enum(['ascending', 'descending']).optional().describe('Order of sorted results')
  }, withErrorHandling(async ({ resourceType, filter, startIndex, count, attributes, excludedAttributes, sortBy, sortOrder }, extra) => {
    const resources = await scimService.getResources(resourceType, { 
      filter, 
      startIndex, 
      count, 
      attributes, 
      excludedAttributes,
      sortBy,
      sortOrder
    });
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(resources, null, 2)
        }
      ]
    };
  }));

  server.tool('getResourceById', 'Retrieve a specific SCIM resource by ID', {
    resourceType: z.string().describe('Type of resource to retrieve (e.g., Users, Groups, etc.)'),
    resourceId: z.string().describe('ID of the resource to retrieve'),
    attributes: z.string().optional().describe('Comma-separated list of attribute names to return'),
    excludedAttributes: z.string().optional().describe('Comma-separated list of attribute names to exclude')
  }, withErrorHandling(async ({ resourceType, resourceId, attributes, excludedAttributes }, extra) => {
    const resource = await scimService.getResourceById(resourceType, resourceId);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(resource, null, 2)
        }
      ]
    };
  }));

  server.tool('createResource', 'Create a new SCIM resource. First use the "resourcetypes" tool to understand available resource types and their schemas, then the "schemas" tool to see required attributes.', {
    resourceType: z.string().describe('Type of resource to create (e.g., Users, Groups, etc.)'),
    body: z.object({}).passthrough().describe('SCIM resource object to create')
  }, withErrorHandling(async ({ resourceType, body }, extra) => {
    const result = await scimService.createResource(resourceType, body);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  }));

  server.tool('updateResource', 'Update an existing SCIM resource (PUT)', {
    resourceType: z.string().describe('Type of resource to update (e.g., Users, Groups, etc.)'),
    resourceId: z.string().describe('ID of the resource to update'),
    body: z.object({}).passthrough().describe('Complete resource representation to replace the existing one')
  }, withErrorHandling(async ({ resourceType, resourceId, body }, extra) => {
    const result = await scimService.updateResource(resourceType, resourceId, body);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  }));

  server.tool('batchOperations', 'Perform multiple POST, PATCH or PUT SCIM operations in a single request (Batch API as per RFC 7644). For path, use something like `/Users` or `/Groups`. Use this tool when you need to create or update multiple resources at once.', {
    operations: z.array(
      z.object({
        method: z.enum(['POST', 'PUT', 'PATCH', 'DELETE']).describe('HTTP method to use for this operation'),
        path: z.string().describe('Resource path relative to the SCIM endpoint (e.g., "/Users", "/Groups/123")'),
        bulkId: z.string().optional().describe('Client-defined ID for correlation in the response'),
        data: z.any().optional().describe('Request body for POST, PUT, or PATCH operations')
      })
    ).describe('Array of operations to perform in the batch'),
    failOnErrors: z.number().optional().describe('Stop processing after N errors (optional)')
  }, withErrorHandling(async ({ operations, failOnErrors }, extra) => {
    const batchRequest = {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
      Operations: operations,
      failOnErrors
    };

    const result = await scimService.batchOperations(batchRequest);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  }));

  server.tool('patchResource', 'Modify an existing SCIM resource (PATCH). For assigning and removing groups from an user, PATCH the Group object and use `add` and `remove` operations.', {
    resourceType: z.string().describe('Type of resource to modify (e.g., Users, Groups, etc.)'),
    resourceId: z.string().describe('ID of the resource to modify'),
    operations: z.array(
      z.object({
        op: z.enum(['add', 'remove', 'replace']).describe('PATCH operation type'),
        path: z.string().optional().describe('Path to the attribute to modify'),
        value: z.any().optional().describe('Value for the operation')
      })
    ).describe('Array of patch operations to perform')
  }, withErrorHandling(async ({ resourceType, resourceId, operations }, extra) => {
    const patchBody = {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: operations
    };
    
    // Call PATCH endpoint using the generic updateResource method
    // This assumes the scimService has a patchResource method (we'll need to implement it)
    const result = await scimService.patchResource(resourceType, resourceId, patchBody);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  }));

  server.tool('deleteResource', 'Delete a SCIM resource', {
    resourceType: z.string().describe('Type of resource to delete (e.g., Users, Groups, etc.)'),
    resourceId: z.string().describe('ID of the resource to delete')
  }, withErrorHandling(async ({ resourceType, resourceId }, extra) => {
    await scimService.deleteResource(resourceType, resourceId);
    return {
      content: [
        {
          type: "text",
          text: `Successfully deleted ${resourceType} with ID ${resourceId}`
        }
      ]
    };
  }));

  server.tool('export', 'Export SCIM resources to a user-specified destination by eliciting export details and generating integration code via MCP sampling.', {}, withErrorHandling(async (_, extra) => {
    let elicitationResult;
    try {
      elicitationResult = await (extra as any).sendRequest({
        method: 'elicitation/create',
        params: {
          message: 'Where should SCIM data be exported? Provide the resource type to export and describe the target system (for example, a CSV file path or database connection details).',
          requestedSchema: {
            type: 'object',
            properties: {
              exportResourceType: {
                type: 'string',
                title: 'SCIM resource type',
                description: 'Example: Users, Groups, or any available resource type.'
              },
              targetDescription: {
                type: 'string',
                title: 'Export destination description',
                description: 'Describe where to send the data, such as a CSV file path, S3 bucket, or database connection instructions.'
              }
            },
            required: ['exportResourceType', 'targetDescription']
          }
        }
      } as any, ElicitResultSchema);
    } catch (error) {
      console.error('Failed to run elicitation for export tool:', error);
      throw new Error('Unable to ask the user for export details. Ensure the client supports MCP elicitation.');
    }

    if (!elicitationResult || elicitationResult.action !== 'accept' || !elicitationResult.content) {
      const action = elicitationResult?.action ?? 'unknown';
      return {
        content: [
          {
            type: 'text',
            text: `Export cancelled by user (action: ${action}).`
          }
        ]
      };
    }

    const rawResourceType = elicitationResult.content.exportResourceType;
    const rawTargetDescription = elicitationResult.content.targetDescription;
    const exportResourceType = typeof rawResourceType === 'string' && rawResourceType.trim().length > 0
      ? rawResourceType.trim()
      : 'Users';
    const targetDescription = typeof rawTargetDescription === 'string' ? rawTargetDescription.trim() : '';

    if (!targetDescription) {
      return {
        content: [
          {
            type: 'text',
            text: 'No export destination information was provided, so no code was generated.'
          }
        ]
      };
    }

    const systemPrompt = [
      'You are an expert integration engineer who produces complete, ready-to-run scripts.',
      'Given a SCIM server endpoint, generate code that retrieves data and writes it to the destination described by the user.',
      'Explain any assumptions clearly and prefer secure handling of credentials (environment variables, secrets managers, etc.).'
    ].join(' ');

    const userPrompt = [
      `SCIM base URL: ${config.scimUrl}.`,
      `Resource type to export: ${exportResourceType}.`,
      `Destination description: ${targetDescription}.`,
      'Output:',
      '- Brief checklist of steps to perform.',
      '- A complete script (choose the most appropriate language) that authenticates with the SCIM server, retrieves the specified resources, and writes them to the destination.',
      '- Include instructions for required dependencies and environment variables.'
    ].join('\n');

    let samplingResult;
    try {
      samplingResult = await (extra as any).sendRequest({
        method: 'sampling/createMessage',
        params: {
          systemPrompt,
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: userPrompt
              }
            }
          ],
          temperature: 0,
          maxTokens: 1200
        }
      }, CreateMessageResultSchema);
    } catch (error) {
      console.error('Failed to generate export code via sampling:', error);
      throw new Error('Unable to generate export code. Ensure the client supports MCP sampling.');
    }

    let generatedText: string;
    if (samplingResult.content.type === 'text') {
      generatedText = samplingResult.content.text;
    } else if (samplingResult.content.type === 'image') {
      generatedText = 'The sampling response was an image, which cannot be rendered as code.';
    } else if (samplingResult.content.type === 'audio') {
      generatedText = 'The sampling response was audio, which cannot be rendered as code.';
    } else {
      generatedText = 'The sampling response type was not recognized.';
    }

    return {
      content: [
        {
          type: 'text',
          text: `Export plan and code generated for ${exportResourceType}:\n\n${generatedText}`
        }
      ]
    };
  }));

  // Retrieve SCIM schema information
  server.tool('schemas', 'Retrieve SCIM schema information', {}, withErrorHandling(async (_, extra) => {
    const schemas = await scimService.getSchemas();
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(schemas, null, 2)
        }
      ]
    };
  }));

  // Retrieve SCIM service provider configuration
  server.tool('serviceProviderConfig', 'Retrieve SCIM service provider configuration including supported features, authentication schemes, and protocol capabilities', {}, withErrorHandling(async (_, extra) => {
    const config = await scimService.getServiceProviderConfig();
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(config, null, 2)
        }
      ]
    };
  }));

  return server;
}


async function runStdioServer() {
  // For stdio mode, get auth and URL from env - both are required
  const authToken = process.env.SCIM_AUTH_TOKEN;
  const scimUrl = process.env.SCIM_URL;
  
  if (!authToken) {
    console.error('Error: SCIM_AUTH_TOKEN environment variable is required for stdio mode');
    process.exit(1);
  }
  
  if (!scimUrl) {
    console.error('Error: SCIM_URL environment variable is required for stdio mode');
    process.exit(1);
  }
  
  // Update config with the required SCIM_URL for this session
  config.scimUrl = scimUrl;
  
  const server = getServer(`Bearer ${authToken}`);
  const transport = new StdioServerTransport();
  console.error('SCIM MCP Server starting in stdio mode...');
  console.error(`SCIM URL: ${config.scimUrl}`);
  await server.connect(transport);
  process.on('SIGINT', async () => {
    console.error('Received SIGINT, shutting down gracefully...');
    await server.close();
    process.exit(0);
  });
}

async function runHttpServer() {
  const app = express();
  app.use(express.json());

  // Store transports for each session type
  const transports = {
    streamable: {} as Record<string, StreamableHTTPServerTransport>,
    sse: {} as Record<string, SSEServerTransport>
  };

  // Handle both /mcp and /mcp/:token routes
  app.post(['/mcp', '/mcp/:token'], async (req: Request, res: Response) => {
    try {
      // Get auth from header or URL parameter
      let authHeader = req.headers.authorization;
      const urlToken = req.params.token;
      
      // If token is provided in URL and no auth header, use URL token
      if (urlToken && !authHeader) {
        authHeader = `Bearer ${urlToken}`;
      }
      
      const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      const server = getServer(authHeader);
      res.on('close', () => {
        console.log('Request closed');
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error('Error handling MCP request:', error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error',
          },
          id: null,
        });
      }
    }
  });

  app.get(['/mcp', '/mcp/:token'], async (req: Request, res: Response) => {
    console.log('Received GET MCP request');
    console.log('Request headers:', req.headers);
    console.log('Request body:', req.body);
    console.log('Request query:', req.query);
    console.log('Request params:', req.params);
    console.log('Request method:', req.method);
    res.writeHead(405).end(JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    }));
  });

  app.delete(['/mcp', '/mcp/:token'], async (req: Request, res: Response) => {
    console.log('Received DELETE MCP request');
    res.writeHead(405).end(JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    }));
  });

  // Legacy SSE endpoint for older clients
  app.get('/sse', async (req, res) => {
    const authHeader = req.headers.authorization;
    // Create SSE transport for legacy clients
    const transport = new SSEServerTransport('/messages', res);
    transports.sse[transport.sessionId] = transport;
    res.on("close", () => {
      delete transports.sse[transport.sessionId];
    });
    const server = getServer(authHeader);
    await server.connect(transport);
  });

  // Legacy message endpoint for older clients
  app.post('/messages', async (req, res) => {
    const sessionId = req.query.sessionId as string;
    const transport = transports.sse[sessionId];
    if (transport) {
      await transport.handlePostMessage(req, res, req.body);
    } else {
      res.status(400).send('No transport found for sessionId');
    }
  });

  // Start server
  const server = app.listen(config.port, () => {
    console.log(`Server running on port ${config.port}`);
    if (config.isDevelopment) {
      console.log('Running in DEVELOPMENT mode with auto-reload enabled');
      console.log('SCIM URL:', config.scimUrl);
      console.log('To disable auto-reload, use: npm run dev');
    }
  });

  // Handle graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
      console.log('HTTP server closed');
    });
  });

  return app;
}

// Main execution logic
if (config.mode === 'stdio' || process.argv.includes('--stdio')) {
  runStdioServer().catch(error => {
    console.error('Failed to start stdio server:', error);
    process.exit(1);
  });
} else {
  runHttpServer().catch(error => {
    console.error('Failed to start HTTP server:', error);
    process.exit(1);
  });
}

// For compatibility with import, export a dummy app (for HTTP mode)
const dummyApp = {};
export default dummyApp;
