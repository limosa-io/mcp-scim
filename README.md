# SCIM MCP Server

A Model Context Protocol (MCP) server that bridges SCIM 2.0 APIs, allowing MCP clients to interact with SCIM resources through standardized tools.

> [!TIP]
> 🚀 **SCIM Playground:** Test this SCIM MCP server live in the **[SCIM Playground](https://scim.dev/playground/modelcontextprotocol/)** before integrating it with your own SCIM server.

<p align="center">
    <a href="https://scim.dev/playground/modelcontextprotocol/">
        <img src="https://img.shields.io/badge/SCIM%20Playground-Try%20It%20Now-1e90ff?style=for-the-badge" alt="SCIM Playground Badge">
    </a>
</p>

## Usage

### Stdio Transport

Add this configuration to your MCP client:

```json
{
  "command": "npx",
  "args": ["github:limosa-io/mcp-scim", "--stdio"],
  "env": {
    "SCIM_URL": "https://your-scim-server.com",
    "SCIM_AUTH_TOKEN": "your-bearer-token"
  }
}
```

### HTTP Transport

For HTTP-based MCP clients.

```json
{
  "url": "http://localhost:3000/mcp",
  "headers": {
    "Authorization": "Bearer your-token"
  },
  "type": "http"
}
```

> **Note:** Make sure to start the HTTP server first using `npx github:limosa-io/mcp-scim` (without --stdio flag). Please set the environment variable `SCIM_URL` and optionally `PORT`.

## Available Tools

| Tool | Description |
|------|-------------|
| `resourcetypes` | List available SCIM resource types |
| `schemas` | Get SCIM schemas and attribute definitions |
| `serviceProviderConfig` | Get server capabilities and configuration |
| `getResources` | Query resources with filtering and pagination |
| `getResourceById` | Retrieve a specific resource by ID |
| `createResource` | Create a new SCIM resource |
| `updateResource` | Update an existing resource (PUT) |
| `patchResource` | Modify a resource with specific operations (PATCH) |
| `deleteResource` | Delete a resource |
| `batchOperations` | Perform multiple operations in a single request |

## Development

### Local Development Setup

```bash
git clone git@github.com:limosa-io/mcp-scim.git
cd mcp-scim
npm install
```

### Development Commands

```bash
npm run dev:watch  # Auto-reload on file changes
npm run dev        # Run once in development mode
npm run build      # Compile TypeScript to JavaScript
npm start          # Run the compiled version
```
