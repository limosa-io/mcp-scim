# SCIM MCP Server

A Model Context Protocol (MCP) server that bridges SCIM 2.0 APIs, allowing MCP clients to interact with SCIM resources through standardized tools.

> [!TIP]
> 🚀 **SCIM Playground:** Test this SCIM MCP server live in the **[SCIM Playground](https://scim.dev/playground/modelcontextprotocol/)** before integrating it with your own SCIM server.

<p align="center">
    <a href="https://scim.dev/playground/modelcontextprotocol/">
        <img src="https://img.shields.io/badge/SCIM%20Playground-Try%20It%20Now-1e90ff?style=for-the-badge" alt="SCIM Playground Badge">
    </a>
</p>

## Quick Start

```bash
npm install
npm start
```

The server runs on `http://localhost:3000` by default.

## Configuration

Set environment variables in `.env` (copy from [.env.example](.env.example)):

```bash
PORT=3000
SCIM_URL=http://localhost:8080
```

## MCP Client Setup

```json
{
  "url": "http://localhost:3000/mcp",
  "headers": {
    "Authorization": "Bearer your-token"
  },
  "type": "http"
}
```

## Available Tools

- **resourcetypes** - List available SCIM resource types
- **getResources** - Query resources with filtering/pagination
- **getResourceById** - Retrieve specific resource
- **createResource** - Create new resource
- **updateResource** - Update existing resource (PUT)
- **patchResource** - Modify resource (PATCH)
- **deleteResource** - Delete resource
- **batchOperations** - Bulk operations
- **schemas** - Get SCIM schemas
- **serviceProviderConfig** - Get server capabilities

## Development

```bash
npm run dev:watch  # Auto-reload on changes
npm run build      # Compile
```
