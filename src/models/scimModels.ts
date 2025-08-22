// SCIM Resource Types
export interface ScimResourceType {
  id: string;
  name: string;
  description?: string;
  schema: string;
  endpoint: string;
  schemaExtensions?: {
    schema: string;
    required: boolean;
  }[];
}

// SCIM Resource schema
export interface ScimResource {
  id: string;
  schemas: string[];
  meta?: {
    resourceType: string;
    created?: string;
    lastModified?: string;
    location?: string;
    version?: string;
  };
  [key: string]: any; // Allow for any additional attributes
}

// SCIM User
export interface ScimUser extends ScimResource {
  userName: string;
  name?: {
    formatted?: string;
    familyName?: string;
    givenName?: string;
    middleName?: string;
    honorificPrefix?: string;
    honorificSuffix?: string;
  };
  displayName?: string;
  emails?: Array<{
    value: string;
    type?: string;
    primary?: boolean;
  }>;
  active?: boolean;
}

// SCIM Group
export interface ScimGroup extends ScimResource {
  displayName: string;
  members?: Array<{
    value: string;
    $ref?: string;
    display?: string;
  }>;
}

// SCIM List Response
export interface ScimListResponse<T extends ScimResource> {
  schemas: string[];
  totalResults: number;
  Resources: T[];
  startIndex?: number;
  itemsPerPage?: number;
}

// SCIM Error Response
export interface ScimError {
  schemas: string[];
  status: string;
  scimType?: string;
  detail?: string;
}

// SCIM Query Parameters
export interface ScimQueryParams {
  filter?: string;
  startIndex?: number;
  count?: number;
  attributes?: string;
  excludedAttributes?: string;
  sortBy?: string;
  sortOrder?: 'ascending' | 'descending';
}

// SCIM Patch Operation
export interface ScimPatchOperation {
  op: 'add' | 'remove' | 'replace';
  path?: string;
  value?: any;
}

// SCIM Patch Request
export interface ScimPatchRequest {
  schemas: string[];
  Operations: ScimPatchOperation[];
}