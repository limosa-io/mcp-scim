import { Request, Response } from 'express';

export interface ResourceServerMetadata {
  resource_id: string;
  resource_documentation?: string;
  resource_scopes?: string[];
  authorization_servers?: string[];
  bearer_methods_supported?: string[];
  resource_signing_alg_values_supported?: string[];
  op_policy_uri?: string;
  op_tos_uri?: string;
}

export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri?: string;
  registration_endpoint?: string;
  response_types_supported?: string[];
  grant_types_supported?: string[];
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
}

export class WellKnownEndpoints {
  private readonly authorizationServerUrl: string;
  private readonly baseMetadata: ResourceServerMetadata;
  private metadataOverrides: Partial<ResourceServerMetadata> = {};
  private authorizationServerMetadataOverrides: Partial<AuthorizationServerMetadata> = {};

  constructor(
    authorizationServerUrl: string, 
    resourceId: string = 'scim-resource-server',
    baseUrl?: string
  ) {
    this.authorizationServerUrl = authorizationServerUrl?.replace(/\/$/, '') ?? '';
    this.baseMetadata = {
      resource_id: resourceId,
      resource_scopes: [
        'resources'
      ],
      authorization_servers: this.authorizationServerUrl ? [this.authorizationServerUrl] : undefined,
      bearer_methods_supported: ['header']
    };
  }

  private buildMetadata(): ResourceServerMetadata {
    const base = {
      ...this.baseMetadata,
      authorization_servers: this.baseMetadata.authorization_servers
        ?? (this.authorizationServerUrl ? [this.authorizationServerUrl] : undefined),
    };

    return {
      ...base,
      ...this.metadataOverrides,
      authorization_servers: this.metadataOverrides.authorization_servers
        ?? base.authorization_servers,
    };
  }

  private buildAuthorizationServerMetadata(): AuthorizationServerMetadata | undefined {
    if (!this.authorizationServerUrl) {
      return undefined;
    }

    const metadata: AuthorizationServerMetadata = {
      issuer: this.authorizationServerUrl,
      authorization_endpoint: `${this.authorizationServerUrl}/authorize`,
      token_endpoint: `${this.authorizationServerUrl}/token`,
      jwks_uri: `${this.authorizationServerUrl}/.well-known/jwks.json`,
      registration_endpoint: `${this.authorizationServerUrl}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
      scopes_supported: this.baseMetadata.resource_scopes,
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'private_key_jwt'],
      code_challenge_methods_supported: ['S256']
    };

    return {
      ...metadata,
      ...this.authorizationServerMetadataOverrides,
      grant_types_supported: this.authorizationServerMetadataOverrides.grant_types_supported
        ?? metadata.grant_types_supported,
      response_types_supported: this.authorizationServerMetadataOverrides.response_types_supported
        ?? metadata.response_types_supported,
      scopes_supported: this.authorizationServerMetadataOverrides.scopes_supported
        ?? metadata.scopes_supported,
      token_endpoint_auth_methods_supported: this.authorizationServerMetadataOverrides.token_endpoint_auth_methods_supported
        ?? metadata.token_endpoint_auth_methods_supported,
      code_challenge_methods_supported: this.authorizationServerMetadataOverrides.code_challenge_methods_supported
        ?? metadata.code_challenge_methods_supported,
    };
  }

  /**
   * Handle /.well-known/oauth-protected-resource endpoint
   */
  getOAuthProtectedResourceMetadata = (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!this.authorizationServerUrl) {
      res.status(500).json({
        error: 'configuration_error',
        error_description: 'AUTHORIZATION_SERVER_URL environment variable is not configured'
      });
      return;
    }
    res.json(this.buildMetadata());
  };

  /**
   * Handle /.well-known/oauth-authorization-server endpoint
   */
  getOAuthAuthorizationServerMetadata = (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const metadata = this.buildAuthorizationServerMetadata();
    if (!metadata) {
      res.status(500).json({
        error: 'configuration_error',
        error_description: 'AUTHORIZATION_SERVER_URL environment variable is not configured'
      });
      return;
    }
    res.json(metadata);
  };

  /**
   * Update metadata configuration
   */
  updateMetadata(updates: Partial<ResourceServerMetadata>) {
    this.metadataOverrides = { ...this.metadataOverrides, ...updates };
  }

  /**
   * Get current metadata
   */
  getMetadata(): ResourceServerMetadata {
    return this.buildMetadata();
  }

  /**
   * Update authorization server metadata configuration
   */
  updateAuthorizationServerMetadata(updates: Partial<AuthorizationServerMetadata>) {
    this.authorizationServerMetadataOverrides = { 
      ...this.authorizationServerMetadataOverrides, 
      ...updates 
    };
  }

  /**
   * Get current authorization server metadata
   */
  getAuthorizationServerMetadata(): AuthorizationServerMetadata | undefined {
    return this.buildAuthorizationServerMetadata();
  }
}
