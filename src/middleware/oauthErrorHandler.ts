import { Request, Response, NextFunction } from 'express';
import { ScimApiError } from '../services/scimService.js';

export interface AuthConfig {
  authorizationServerUrl: string;
  resourceMetadataUrl: string;
}

/**
 * Simple OAuth error handler that adds WWW-Authenticate headers 
 * when authentication errors occur from the backend SCIM server
 */
export class OAuthErrorHandler {
  private config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
  }

  /**
   * Handle SCIM API errors and add WWW-Authenticate headers for auth errors
   */
  handleScimError(error: ScimApiError, res: Response): void {
    if (ScimApiError.isAuthenticationError(error)) {
      this.addWwwAuthenticateHeader(res, error);
    }
    
    // Forward the original error response
    res.status(error.statusCode).json(error.responseBody);
  }

  /**
   * Add WWW-Authenticate header for authentication errors
   * Uses the original WWW-Authenticate header from SCIM server if available,
   * otherwise constructs our own with resource server metadata
   */
  private addWwwAuthenticateHeader(res: Response, error: ScimApiError): void {
    // If the SCIM server provided a WWW-Authenticate header, use that
    if (error.wwwAuthenticate) {
      res.set('WWW-Authenticate', error.wwwAuthenticate);
      return;
    }
    
    // Otherwise, construct our own WWW-Authenticate header
    let wwwAuthenticateHeader = `Bearer resource_metadata="${this.config.resourceMetadataUrl}"`;
    
    // Add error information if it's an authorization error
    if (error.statusCode === 403) {
      wwwAuthenticateHeader += ', error="insufficient_scope"';
      wwwAuthenticateHeader += ', error_description="Insufficient scope for the requested operation"';
    } else if (error.statusCode === 401) {
      wwwAuthenticateHeader += ', error="invalid_token"';
      wwwAuthenticateHeader += ', error_description="The access token is invalid or expired"';
    }
    
    res.set('WWW-Authenticate', wwwAuthenticateHeader);
  }
}

/**
 * Middleware to pass through Authorization headers to the backend SCIM server
 */
export function createAuthPassthroughMiddleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    // Simply pass through - the authorization header will be forwarded to the backend
    next();
  };
}