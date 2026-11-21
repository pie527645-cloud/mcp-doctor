import readline from 'node:readline';

interface RpcRequest {
  jsonrpc: string;
  id?: number | string;
  method: string;
  params?: Record<string, unknown>;
}

const TOOLS = [
  {
    name: 'search_docs',
    description: 'Search official documentation pages by keyword query and return matching section summaries.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query terms.',
        },
        limit: {
          type: 'integer',
          description: 'Maximum number of results to return (1 to 20).',
        },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_package_info',
    description: 'Retrieve public package version, license, and dependency count from registry metadata.',
    inputSchema: {
      type: 'object',
      properties: {
        packageName: {
          type: 'string',
          description: 'Exact package identifier.',
        },
      },
      required: ['packageName'],
      additionalProperties: false,
    },
  },
  {
    name: 'format_markdown_table',
    description: 'Convert an array of key-value records into a formatted Markdown table string.',
    inputSchema: {
      type: 'object',
      properties: {
        columns: {
          type: 'array',
          description: 'Ordered column names to render.',
        },
      },
      required: ['columns'],
      additionalProperties: false,
    },
  },
];

const RESOURCES = [
  {
    uri: 'docs://guide/getting-started',
    name: 'Getting Started Guide',
    description: 'Overview of configuration and supported commands.',
    mimeType: 'text/markdown',
  },
];

const PROMPTS = [
  {
    name: 'summarize_release_notes',
    description: 'Summarize version changelog items into concise bullet points.',
  },
];

function send(payload: unknown): void {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let req: RpcRequest;
  try {
    req = JSON.parse(trimmed) as RpcRequest;
  } catch {
    return;
  }

  if (req.id === undefined) {
    // Notification (such as notifications/initialized)
    return;
  }

  switch (req.method) {
    case 'initialize':
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
            resources: {},
            prompts: {},
          },
          serverInfo: {
            name: 'clean-docs-mcp',
            version: '1.2.0',
          },
        },
      });
      break;
    case 'tools/list':
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: { tools: TOOLS },
      });
      break;
    case 'resources/list':
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: { resources: RESOURCES },
      });
      break;
    case 'prompts/list':
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: { prompts: PROMPTS },
      });
      break;
    default:
      send({
        jsonrpc: '2.0',
        id: req.id,
        error: { code: -32601, message: `Method not found: ${req.method}` },
      });
      break;
  }
});
