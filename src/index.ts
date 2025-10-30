#!/usr/bin/env node

import express, { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import https from 'https';
import { ScimService, ScimApiError } from './services/scimService.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from "zod";
import dotenv from 'dotenv';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { CreateMessageResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { OAuthErrorHandler, AuthConfig } from './middleware/oauthErrorHandler.js';
import { WellKnownEndpoints } from './endpoints/wellKnown.js';

// Load environment variables from .env file
dotenv.config();

// Configuration
const config = {
  port: process.env.PORT || 3000,
  scimUrl: process.env.SCIM_URL || 'http://localhost:8080',
  isDevelopment: process.env.NODE_ENV === 'development',
  mode: process.env.MCP_MODE || (process.argv.includes('--stdio') ? 'stdio' : 'http'),
  logRequests: process.env.LOG_REQUESTS === 'true',
  // SSL/TLS configuration
  ssl: {
    rejectUnauthorized: process.env.SSL_REJECT_UNAUTHORIZED !== 'false', // Default to true for security
    timeout: parseInt(process.env.SSL_TIMEOUT || '30000')
  },
  oauth: {
    authorizationServerUrl: process.env.AUTHORIZATION_SERVER_URL || 'https://auth-server.example.com',
    baseUrl: process.env.BASE_URL || 'http://localhost:3000'
  }
};

// OAuth configuration
let oauthConfig: AuthConfig;
let oauthErrorHandler: OAuthErrorHandler;
let wellKnownEndpoints: WellKnownEndpoints;

try {
  const resourceMetadataUrl = `${config.oauth.baseUrl}/.well-known/oauth-protected-resource`;
  
  oauthConfig = {
    authorizationServerUrl: config.oauth.authorizationServerUrl,
    resourceMetadataUrl
  };

  oauthErrorHandler = new OAuthErrorHandler(oauthConfig);
  wellKnownEndpoints = new WellKnownEndpoints(
    config.oauth.authorizationServerUrl,
    'scim-resource-server',
    config.oauth.baseUrl
  );

  console.log('OAuth 2.1 Resource Server configured');
  console.log(`Authorization Server: ${config.oauth.authorizationServerUrl}`);
  console.log(`Resource Metadata URL: ${resourceMetadataUrl}`);
} catch (error) {
  console.error('Failed to configure OAuth:', error);
  process.exit(1);
}

/**
 * Request logging middleware
 */
function requestLogger(req: Request, res: Response, next: NextFunction): void {
  if (config.logRequests) {
    const timestamp = new Date().toISOString();
    const method = req.method;
    const url = req.originalUrl || req.url;
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'unknown';
    const contentLength = req.get('Content-Length') || '0';
    const authHeader = req.get('Authorization') || 'none';
    
    console.log(`\n[${timestamp}] Incoming HTTP Request:`);
    console.log(`  Method: ${method}`);
    console.log(`  URL: ${url}`);
    console.log(`  IP: ${ip}`);
    console.log(`  User-Agent: ${userAgent}`);
    console.log(`  Content-Length: ${contentLength}`);
    console.log(`  Authorization: ${authHeader.length > 20 ? authHeader.substring(0, 20) + '...' : authHeader}`);
    
    // Log request body if present
    if (req.body && Object.keys(req.body).length > 0) {
      const bodyStr = JSON.stringify(req.body, null, 2);
      const truncatedBody = bodyStr.length > 1000 
        ? bodyStr.substring(0, 1000) + '...[truncated]' 
        : bodyStr;
      console.log(`  Request Body: ${truncatedBody}`);
    }

    // Log whether this request is handled locally or forwarded to the SCIM server
    const isLocalWellKnownRequest = req.path.startsWith('/.well-known/oauth-protected-resource');
    if (isLocalWellKnownRequest) {
      console.log('  Handled internally by well-known endpoint');
    } else {
      console.log(`  Forwarded to SCIM Server: ${config.scimUrl}`);
    }

    // Override res.json to log response
    const originalJson = res.json;
    res.json = function(body: any) {
      if (config.logRequests) {
        const responseTimestamp = new Date().toISOString();
        console.log(`\n[${responseTimestamp}] HTTP Response:`);
        console.log(`  Status: ${res.statusCode}`);
        
        // Log response body (truncated if too large)
        if (body) {
          const bodyStr = typeof body === 'string' 
            ? body 
            : JSON.stringify(body, null, 2);
          const truncatedBody = bodyStr.length > 1000 
            ? bodyStr.substring(0, 1000) + '...[truncated]' 
            : bodyStr;
          console.log(`  Response Body: ${truncatedBody}`);
        }
      }
      return originalJson.call(this, body);
    };
  }
  next();
}

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
 * Check if request has valid authentication token
 * Returns 401 with WWW-Authenticate header if missing or malformed
 */
function checkAuthentication(req: Request, res: Response): boolean {
  // Get auth from header or URL parameter
  let authHeader = req.headers.authorization;
  let urlToken = req.params.token as string | undefined;

  // Support tokens supplied as query parameters for clients that URL-encode slashes
  if (!urlToken && typeof req.query.token === 'string') {
    urlToken = req.query.token;
  }
  
  // If token is provided in URL and no auth header, use URL token
  if (urlToken && !authHeader) {
    authHeader = `Bearer ${urlToken}`;
  }

  // If no authentication is provided at all, return 401
  if (!authHeader && !urlToken) {
    const wwwAuthenticate = `Bearer resource_metadata="${oauthConfig.resourceMetadataUrl}", error="invalid_request", error_description="Authentication required"`;
    res.set('WWW-Authenticate', wwwAuthenticate);
    res.status(401).json({
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message: 'Authentication required',
        data: {
          type: 'oauth2_authentication_error',
          error: 'invalid_request',
          error_description: 'Authentication required',
          authorization_server: oauthConfig.authorizationServerUrl,
          resource_metadata: oauthConfig.resourceMetadataUrl
        }
      },
      id: null,
    });
    return false;
  }

  return true;
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
        let errorMessage = `Error (${error.statusCode}): ${error.message}`;
        
        // Add OAuth information for authentication errors
        if (ScimApiError.isAuthenticationError(error)) {
          errorMessage += '\n\nOAuth 2.1 Resource Server - Authentication Error:';
          errorMessage += '\nThis MCP server acts as an OAuth 2.1 Resource Server.';
          
          // Use WWW-Authenticate header from SCIM server if available, otherwise construct our own
          if (error.wwwAuthenticate) {
            errorMessage += `\n\nOriginal WWW-Authenticate from SCIM server:\n${error.wwwAuthenticate}`;
          }
          
          // Add our resource server information
          if (error.statusCode === 401) {
            errorMessage += '\n- Error: invalid_token';
            errorMessage += '\n- Description: The access token is invalid or expired';
            errorMessage += `\n- MCP Resource Server WWW-Authenticate: Bearer resource_metadata="${oauthConfig.resourceMetadataUrl}", error="invalid_token", error_description="The access token is invalid or expired"`;
          } else if (error.statusCode === 403) {
            errorMessage += '\n- Error: insufficient_scope';
            errorMessage += '\n- Description: Insufficient scope for the requested operation';
            errorMessage += `\n- MCP Resource Server WWW-Authenticate: Bearer resource_metadata="${oauthConfig.resourceMetadataUrl}", error="insufficient_scope", error_description="Insufficient scope for the requested operation"`;
          }
          
          errorMessage += `\n\nOAuth 2.1 Resource Server Information:`;
          errorMessage += `\n- Authorization Server: ${oauthConfig.authorizationServerUrl}`;
          errorMessage += `\n- Resource Metadata: ${oauthConfig.resourceMetadataUrl}`;
          errorMessage += `\n\nTo obtain a valid access token:`;
          errorMessage += `\n1. Register your client with the authorization server`;
          errorMessage += `\n2. Request an access token using the OAuth 2.1 authorization code flow`;
          errorMessage += `\n3. Include the token in the Authorization header: "Bearer <your-token>"`;
        }
        
        errorMessage += `\n\nSCIM Server Response:\n${JSON.stringify(error.responseBody, null, 2)}`;
        
        return {
          content: [
            {
              type: "text",
              text: errorMessage
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
  const scimService = new ScimService(config.scimUrl, authToken, config.logRequests);
  
  // Configure SSL/TLS settings
  scimService.configureHttpsAgent({ 
    rejectUnauthorized: config.ssl.rejectUnauthorized,
    timeout: config.ssl.timeout
  });
  
  if (config.logRequests) {
    console.log(`SSL Configuration: rejectUnauthorized=${config.ssl.rejectUnauthorized}, timeout=${config.ssl.timeout}ms`);
    if (!config.ssl.rejectUnauthorized) {
      console.warn('WARNING: SSL certificate verification is disabled. Only use this in development!');
    }
  }
  
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
  
  // Add request logging middleware if enabled
  app.use(requestLogger);

  // Store transports for each session type
  const transports = {
    streamable: {} as Record<string, StreamableHTTPServerTransport>,
    sse: {} as Record<string, SSEServerTransport>
  };

  // OAuth 2.1 Well-known endpoints (publicly accessible)
  const forwardWellKnownRequest = async (
    req: Request,
    res: Response,
    normalizedPath: string
  ) => {
    try {
      const authorizationServerUrl = config.oauth.authorizationServerUrl?.trim();
      if (!authorizationServerUrl) {
        res.status(500).json({
          error: 'configuration_error',
          error_description: 'AUTHORIZATION_SERVER_URL environment variable is not configured'
        });
        return;
      }

      const requestUrl = new URL(req.originalUrl, config.oauth.baseUrl);
      const targetUrlObj = new URL(normalizedPath, authorizationServerUrl);
      targetUrlObj.search = requestUrl.search;
      const targetUrl = targetUrlObj.toString();
      const headers: Record<string, string> = {};
      const acceptHeader = req.get('Accept');
      if (acceptHeader) {
        headers['Accept'] = acceptHeader;
      }
      const authHeader = req.get('Authorization');
      if (authHeader) {
        headers['Authorization'] = authHeader;
      }

      const httpsAgent = targetUrl.startsWith('https')
        ? new https.Agent({
            rejectUnauthorized: config.ssl.rejectUnauthorized,
            timeout: config.ssl.timeout
          })
        : undefined;

      const response = await axios.get(targetUrl, {
        responseType: 'arraybuffer',
        headers,
        httpsAgent,
        validateStatus: () => true
      });

      // Pass through selected headers
      const hopByHopHeaders = new Set([
        'transfer-encoding',
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'upgrade'
      ]);

      Object.entries(response.headers).forEach(([header, value]) => {
        if (!value) {
          return;
        }
        if (hopByHopHeaders.has(header.toLowerCase())) {
          return;
        }
        if (Array.isArray(value)) {
          res.setHeader(header, value);
        } else {
          res.setHeader(header, value);
        }
      });

      const body = response.data ? Buffer.from(response.data) : undefined;
      if (body) {
        res.status(response.status).send(body);
      } else {
        res.status(response.status).end();
      }
    } catch (error) {
      console.error(`Error forwarding ${normalizedPath} request:`, error);
      const errorDescription = `Failed to retrieve ${normalizedPath} metadata from authorization server`;
      res.status(502).json({
        error: 'bad_gateway',
        error_description: errorDescription
      });
    }
  };

  app.get(/^\/\.well-known\/oauth-authorization-server(?:\/.*)?$/, async (req: Request, res: Response) => {
    await forwardWellKnownRequest(req, res, '/.well-known/oauth-authorization-server');
  });

  app.get(/^\/\.well-known\/openid-configuration(?:\/.*)?$/, async (req: Request, res: Response) => {
    await forwardWellKnownRequest(req, res, '/.well-known/openid-configuration');
  });
  app.get(/^\/\.well-known\/oauth-protected-resource(?:\/.*)?$/, (req: Request, res: Response, next: NextFunction) => {
    req.url = '/.well-known/oauth-protected-resource' + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '');
    wellKnownEndpoints.getOAuthProtectedResourceMetadata(req, res);
  });

  app.get('/', (req: Request, res: Response) => {
    res.send('SCIM MCP Server is running with OAuth 2.1 Resource Server support');
  });



  // Handle both /mcp and /mcp/:token routes
  app.post(['/mcp', '/mcp/:token'], async (req: Request, res: Response) => {
    try {
      // Check authentication before processing
      if (!checkAuthentication(req, res)) {
        return; // Response already sent by checkAuthentication
      }

      // Get auth from header or URL parameter
      let authHeader = req.headers.authorization;
      let urlToken = req.params.token as string | undefined;

      // Support tokens supplied as query parameters for clients that URL-encode slashes
      if (!urlToken && typeof req.query.token === 'string') {
        urlToken = req.query.token;
      }
      
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
      
      // Handle authentication errors with proper WWW-Authenticate headers
      if (error instanceof ScimApiError && ScimApiError.isAuthenticationError(error)) {
        oauthErrorHandler.handleScimError(error, res);
        return;
      }
      
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
    try {
      const authHeader = req.headers.authorization;
      
      // Check for authentication (but allow SSE to proceed - errors will be handled per-message)
      if (!authHeader) {
        const wwwAuthenticate = `Bearer resource_metadata="${oauthConfig.resourceMetadataUrl}", error="invalid_request", error_description="Authentication required"`;
        res.set('WWW-Authenticate', wwwAuthenticate);
        res.status(401).json({
          error: 'Authentication required',
          authorization_server: oauthConfig.authorizationServerUrl,
          resource_metadata: oauthConfig.resourceMetadataUrl
        });
        return;
      }

      // Create SSE transport for legacy clients
      const transport = new SSEServerTransport('/messages', res);
      transports.sse[transport.sessionId] = transport;
      res.on("close", () => {
        delete transports.sse[transport.sessionId];
      });
      const server = getServer(authHeader);
      await server.connect(transport);
    } catch (error) {
      console.error('Error handling SSE request:', error);
      if (error instanceof ScimApiError && ScimApiError.isAuthenticationError(error)) {
        oauthErrorHandler.handleScimError(error, res);
        return;
      }
      if (!res.headersSent) {
        res.status(500).json({
          error: 'Internal server error'
        });
      }
    }
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

  // Start server and return a promise that keeps the process alive
  return new Promise<void>((resolve, reject) => {
    const server = app.listen(config.port, () => {
      console.log(`Server running on port ${config.port}`);
      if (config.isDevelopment) {
        console.log('Running in DEVELOPMENT mode with auto-reload enabled');
        console.log('SCIM URL:', config.scimUrl);
        console.log('To disable auto-reload, use: npm run dev');
      }
      // Don't resolve - keep the process alive
    });

    server.on('error', (error) => {
      console.error('Server error:', error);
      reject(error);
    });

    // Handle graceful shutdown
    process.on('SIGTERM', () => {
      console.log('SIGTERM signal received: closing HTTP server');
      server.close(() => {
        console.log('HTTP server closed');
        resolve();
      });
    });

    process.on('SIGINT', () => {
      console.log('SIGINT signal received: closing HTTP server');
      server.close(() => {
        console.log('HTTP server closed');
        resolve();
      });
    });
  });
}

// Main execution logic
async function main() {
  try {
    if (config.mode === 'stdio' || process.argv.includes('--stdio')) {
      await runStdioServer();
    } else {
      await runHttpServer();
    }
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
main();

// For compatibility with import, export a dummy app (for HTTP mode)
const dummyApp = {};
export default dummyApp;
