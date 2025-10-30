import axios, { AxiosInstance, AxiosError } from 'axios';
import https from 'https';
import { 
  ScimResourceType, 
  ScimResource, 
  ScimListResponse,
  ScimQueryParams,
  ScimPatchRequest,
  ScimError
} from '../models/scimModels.js';

// Custom error class to preserve the status code and response body
export class ScimApiError extends Error {
  statusCode: number;
  responseBody: any;
  responseHeaders: any;
  isAuthError: boolean;
  wwwAuthenticate?: string;

  constructor(statusCode: number, responseBody: any, message: string, responseHeaders?: any) {
    super(message);
    this.name = 'ScimApiError';
    this.statusCode = statusCode;
    this.responseBody = responseBody;
    this.responseHeaders = responseHeaders || {};
    this.isAuthError = statusCode === 401 || statusCode === 403;
    
    // Extract WWW-Authenticate header if present
    if (responseHeaders && (responseHeaders['www-authenticate'] || responseHeaders['WWW-Authenticate'])) {
      this.wwwAuthenticate = responseHeaders['www-authenticate'] || responseHeaders['WWW-Authenticate'];
    }
  }
  
  // Check if this is an authentication/authorization error
  static isAuthenticationError(error: ScimApiError): boolean {
    return error.isAuthError;
  }
}

export class ScimService {
  private client: AxiosInstance;
  private baseUrl: string;
  private logRequests: boolean;
  
  constructor(baseUrl: string, authToken?: string, logRequests: boolean = false) {
    this.baseUrl = baseUrl;
    this.logRequests = logRequests;
    
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 30000, // 30 second timeout
      headers: {
        'Content-Type': 'application/scim+json',
        ...(authToken && { 'Authorization': authToken.startsWith('Bearer ') ? authToken : `Bearer ${authToken}` })
      },
      // Enhanced error handling for SSL/TLS issues
      validateStatus: function (status) {
        // Accept all status codes so we can log them properly
        return status >= 200 && status < 600;
      }
    });

    // Add request and response interceptors for detailed logging
    this.setupRequestInterceptors();
  }

  // Setup request and response interceptors for detailed logging
  private setupRequestInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        if (this.logRequests) {
          const timestamp = new Date().toISOString();
          const url = `${config.baseURL}${config.url}`;
          const method = config.method?.toUpperCase();
          const headers = JSON.stringify(config.headers, null, 2);
          
          console.log(`\n[${timestamp}] SCIM Request:`);
          console.log(`  Method: ${method}`);
          console.log(`  URL: ${url}`);
          console.log(`  Headers: ${headers}`);
          
          // Log request body if present
          if (config.data) {
            const bodyStr = typeof config.data === 'string' 
              ? config.data 
              : JSON.stringify(config.data, null, 2);
            console.log(`  Request Body: ${bodyStr}`);
          }
        }
        return config;
      },
      (error) => {
        if (this.logRequests) {
          console.error('SCIM Request Error:', error);
        }
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        if (this.logRequests) {
          const timestamp = new Date().toISOString();
          const url = response.config.url;
          const status = response.status;
          const statusText = response.statusText;
          const headers = JSON.stringify(response.headers, null, 2);
          
          console.log(`\n[${timestamp}] SCIM Response:`);
          console.log(`  URL: ${url}`);
          console.log(`  Status: ${status} ${statusText}`);
          console.log(`  Response Headers: ${headers}`);
          
          // Log response body (truncated if too large)
          if (response.data) {
            const bodyStr = typeof response.data === 'string' 
              ? response.data 
              : JSON.stringify(response.data, null, 2);
            const truncatedBody = bodyStr.length > 2000 
              ? bodyStr.substring(0, 2000) + '...[truncated]' 
              : bodyStr;
            console.log(`  Response Body: ${truncatedBody}`);
          }
        }
        return response;
      },
      (error) => {
        if (this.logRequests) {
          const timestamp = new Date().toISOString();
          console.log(`\n[${timestamp}] SCIM Request Error:`);
          
          if (error.response) {
            // The server responded with an error status
            const url = error.config?.url;
            const status = error.response.status;
            const statusText = error.response.statusText;
            const headers = JSON.stringify(error.response.headers, null, 2);
            
            console.log(`  Type: HTTP Error Response`);
            console.log(`  URL: ${url}`);
            console.log(`  Status: ${status} ${statusText}`);
            console.log(`  Response Headers: ${headers}`);
            
            // Log error response body
            if (error.response.data) {
              const bodyStr = typeof error.response.data === 'string' 
                ? error.response.data 
                : JSON.stringify(error.response.data, null, 2);
              console.log(`  Error Response Body: ${bodyStr}`);
            }
          } else if (error.request) {
            // The request was made but no response was received
            console.log(`  Type: Network/Connection Error`);
            console.log(`  URL: ${error.config?.url}`);
            console.log(`  Message: ${error.message}`);
            console.log(`  Code: ${error.code || 'N/A'}`);
            
            // Log SSL/TLS specific errors
            if (error.code === 'ECONNREFUSED') {
              console.log(`  Details: Connection refused - server may be down or unreachable`);
            } else if (error.code === 'ENOTFOUND') {
              console.log(`  Details: DNS resolution failed - hostname not found`);
            } else if (error.code === 'CERT_HAS_EXPIRED') {
              console.log(`  Details: SSL certificate has expired`);
            } else if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
              console.log(`  Details: SSL certificate verification failed`);
            } else if (error.code === 'SELF_SIGNED_CERT_IN_CHAIN') {
              console.log(`  Details: Self-signed certificate in chain`);
            } else if (error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
              console.log(`  Details: Self-signed certificate`);
            } else if (error.code?.includes('SSL') || error.code?.includes('TLS')) {
              console.log(`  Details: SSL/TLS error - ${error.message}`);
            }
            
            // Log request details that failed
            if (error.config) {
              console.log(`  Request Method: ${error.config.method?.toUpperCase()}`);
              console.log(`  Request Headers: ${JSON.stringify(error.config.headers, null, 2)}`);
              if (error.config.timeout) {
                console.log(`  Timeout: ${error.config.timeout}ms`);
              }
            }
          } else {
            // Something happened in setting up the request
            console.log(`  Type: Request Setup Error`);
            console.log(`  Message: ${error.message}`);
            console.log(`  Stack: ${error.stack}`);
          }
        }
        
        return Promise.reject(error);
      }
    );
  }
  
  // Method to update authorization header for a request
  setAuthToken(authToken: string) {
    this.client.defaults.headers['Authorization'] = authToken.startsWith('Bearer ') ? authToken : `Bearer ${authToken}`;
  }

  // Method to configure SSL/TLS settings for development (use with caution)
  configureHttpsAgent(options: { rejectUnauthorized?: boolean; timeout?: number } = {}) {
    const httpsAgent = new https.Agent({
      rejectUnauthorized: options.rejectUnauthorized ?? true,
      timeout: options.timeout || 30000
    });
    
    this.client.defaults.httpsAgent = httpsAgent;
    
    if (this.logRequests) {
      console.log(`HTTPS Agent configured with rejectUnauthorized: ${httpsAgent.options.rejectUnauthorized}`);
    }
  }
  
  // Get all available resource types
  async getResourceTypes(): Promise<ScimResourceType[]> {
    try {
      const response = await this.client.get('/ResourceTypes');
      return response.data.Resources || [];
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const errorMessage = this.buildErrorMessage('Error fetching resource types', error);
        throw this.createScimApiError(error, errorMessage);
      }
      console.error('Error fetching resource types:', error);
      throw error;
    }
  }

  // Helper method to build detailed error messages
  private buildErrorMessage(baseMessage: string, error: AxiosError): string {
    let message = baseMessage;
    
    if (error.code) {
      message += ` (${error.code})`;
    }
    
    if (error.response) {
      message += ` - Server responded with ${error.response.status}: ${error.response.statusText}`;
    } else if (error.request) {
      message += ` - No response received from server`;
      if (error.code === 'ECONNREFUSED') {
        message += ` (Connection refused)`;
      } else if (error.code === 'ENOTFOUND') {
        message += ` (Host not found)`;
      } else if (error.code?.includes('SSL') || error.code?.includes('TLS') || error.code?.includes('CERT')) {
        message += ` (SSL/TLS error)`;
      }
    }
    
    return message;
  }

  // Helper method to create ScimApiError with response headers
  private createScimApiError(error: AxiosError, message: string): ScimApiError {
    return new ScimApiError(
      error.response?.status || 500, 
      error.response?.data, 
      message,
      error.response?.headers
    );
  }
  
  // Get a specific resource type
  async getResourceType(resourceTypeId: string): Promise<ScimResourceType> {
    try {
      const response = await this.client.get(`/ResourceTypes/${resourceTypeId}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const errorMessage = this.buildErrorMessage(`Error fetching resource type ${resourceTypeId}`, error);
        throw this.createScimApiError(error, errorMessage);
      }
      console.error(`Error fetching resource type ${resourceTypeId}:`, error);
      throw error;
    }
  }
  
  // Get resources of a specific type with filtering capability
  async getResources<T extends ScimResource>(
    resourceType: string, 
    params?: ScimQueryParams
  ): Promise<ScimListResponse<T>> {
    try {
      // Convert query parameters to URL query string
      const queryParams = new URLSearchParams();
      
      if (params) {
        if (params.filter) queryParams.append('filter', params.filter);
        if (params.startIndex) queryParams.append('startIndex', params.startIndex.toString());
        if (params.count) queryParams.append('count', params.count.toString());
        if (params.attributes) queryParams.append('attributes', params.attributes);
        if (params.excludedAttributes) queryParams.append('excludedAttributes', params.excludedAttributes);
        if (params.sortBy) queryParams.append('sortBy', params.sortBy);
        if (params.sortOrder) queryParams.append('sortOrder', params.sortOrder);
      }
      
      const queryString = queryParams.toString();
      const url = `/${resourceType}${queryString ? '?' + queryString : ''}`;
      
      const response = await this.client.get(url);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, `Error fetching ${resourceType}`);
      }
      console.error(`Error fetching ${resourceType}:`, error);
      throw error;
    }
  }
  
  // Get a specific resource by ID
  async getResourceById<T extends ScimResource>(
    resourceType: string,
    resourceId: string,
    params?: Pick<ScimQueryParams, 'attributes' | 'excludedAttributes'>
  ): Promise<T> {
    try {
      // Convert query parameters to URL query string
      const queryParams = new URLSearchParams();
      
      if (params) {
        if (params.attributes) queryParams.append('attributes', params.attributes);
        if (params.excludedAttributes) queryParams.append('excludedAttributes', params.excludedAttributes);
      }
      
      const queryString = queryParams.toString();
      const url = `/${resourceType}/${resourceId}${queryString ? '?' + queryString : ''}`;
      
      const response = await this.client.get(url);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, `Error fetching ${resourceType} with ID ${resourceId}`);
      }
      console.error(`Error fetching ${resourceType} with ID ${resourceId}:`, error);
      throw error;
    }
  }
  
  // Create a new resource
  async createResource<T extends ScimResource>(
    resourceType: string,
    resource: Omit<T, 'id'>
  ): Promise<T> {
    try {
      const response = await this.client.post(`/${resourceType}`, resource);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, `Error creating ${resourceType}`);
      }
      console.error(`Error creating ${resourceType}:`, error);
      throw error;
    }
  }
  
  // Update an existing resource (PUT)
  async updateResource<T extends ScimResource>(
    resourceType: string,
    resourceId: string,
    resource: Partial<T>
  ): Promise<T> {
    try {
      const response = await this.client.put(`/${resourceType}/${resourceId}`, resource);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, `Error updating ${resourceType} with ID ${resourceId}`);
      }
      console.error(`Error updating ${resourceType} with ID ${resourceId}:`, error);
      throw error;
    }
  }
  
  // Patch an existing resource (PATCH)
  async patchResource<T extends ScimResource>(
    resourceType: string,
    resourceId: string,
    patchRequest: ScimPatchRequest
  ): Promise<T> {
    try {
      const response = await this.client.patch(`/${resourceType}/${resourceId}`, patchRequest);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, `Error patching ${resourceType} with ID ${resourceId}`);
      }
      console.error(`Error patching ${resourceType} with ID ${resourceId}:`, error);
      throw error;
    }
  }
  
  // Delete a resource
  async deleteResource(resourceType: string, resourceId: string): Promise<void> {
    try {
      await this.client.delete(`/${resourceType}/${resourceId}`);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, `Error deleting ${resourceType} with ID ${resourceId}`);
      }
      console.error(`Error deleting ${resourceType} with ID ${resourceId}:`, error);
      throw error;
    }
  }

  // Retrieve SCIM schemas
  async getSchemas(): Promise<any> {
    try {
      const response = await this.client.get('/Schemas');
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const errorMessage = this.buildErrorMessage('Error fetching SCIM schemas', error);
        throw this.createScimApiError(error, errorMessage);
      }
      console.error('Error fetching SCIM schemas:', error);
      throw error;
    }
  }

  // Retrieve SCIM Service Provider configuration
  async getServiceProviderConfig(): Promise<any> {
    try {
      const response = await this.client.get('/ServiceProviderConfig');
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const errorMessage = this.buildErrorMessage('Error fetching service provider configuration', error);
        throw this.createScimApiError(error, errorMessage);
      }
      console.error('Error fetching service provider configuration:', error);
      throw error;
    }
  }
  
  // Perform batch operations according to SCIM RFC 7644
  async batchOperations(batchRequest: {
    schemas?: string[];
    Operations: Array<{
      method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
      path: string;
      bulkId?: string;
      data?: any;
    }>;
    failOnErrors?: number;
  }): Promise<{
    schemas: string[];
    Operations: Array<{
      location?: string;
      method: string;
      bulkId?: string;
      status: string;
      response?: any;
    }>;
  }> {
    try {
      // Ensure the request has the proper SCIM batch schema
      const request = {
        schemas: batchRequest.schemas || ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
        Operations: batchRequest.Operations,
        failOnErrors: batchRequest.failOnErrors
      };

      // Send the batch request to the SCIM server
      const response = await this.client.post('/Bulk', request);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.createScimApiError(error, 'Error performing batch operations');
      }
      console.error('Error performing batch operations:', error);
      throw error;
    }
  }
}