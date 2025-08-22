import axios, { AxiosInstance, AxiosError } from 'axios';
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

  constructor(statusCode: number, responseBody: any, message: string) {
    super(message);
    this.name = 'ScimApiError';
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
}

export class ScimService {
  private client: AxiosInstance;
  private baseUrl: string;
  
  constructor(baseUrl: string, authToken?: string) {
    this.baseUrl = baseUrl;
    
    this.client = axios.create({
      baseURL: baseUrl,
      headers: {
        'Content-Type': 'application/scim+json',
        ...(authToken && { 'Authorization': `Bearer ${authToken}` })
      }
    });
  }
  
  // Get all available resource types
  async getResourceTypes(): Promise<ScimResourceType[]> {
    try {
      const response = await this.client.get('/ResourceTypes');
      return response.data.Resources || [];
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new ScimApiError(error.response?.status || 500, error.response?.data, 'Error fetching resource types');
      }
      console.error('Error fetching resource types:', error);
      throw error;
    }
  }
  
  // Get a specific resource type
  async getResourceType(resourceTypeId: string): Promise<ScimResourceType> {
    try {
      const response = await this.client.get(`/ResourceTypes/${resourceTypeId}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error fetching resource type ${resourceTypeId}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error fetching ${resourceType}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error fetching ${resourceType} with ID ${resourceId}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error creating ${resourceType}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error updating ${resourceType} with ID ${resourceId}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error patching ${resourceType} with ID ${resourceId}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, `Error deleting ${resourceType} with ID ${resourceId}`);
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, 'Error fetching SCIM schemas');
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, 'Error fetching service provider configuration');
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
        throw new ScimApiError(error.response?.status || 500, error.response?.data, 'Error performing batch operations');
      }
      console.error('Error performing batch operations:', error);
      throw error;
    }
  }
}