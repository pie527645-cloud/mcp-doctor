import type { McpToolDefinition, ToolTokenBreakdown } from '../types.js';

/** Fixed structural wrapper token overhead per tool declaration in LLM system prompts. */
const TOOL_WRAPPER_OVERHEAD_TOKENS = 12;

/**
 * Estimates BPE token count (`cl100k_base` / modern LLM approximation) deterministically
 * without external native dependencies.
 */
export function estimateTokens(text: string): number {
  if (!text) return 0;

  // Segment into word runs, number runs, JSON/code punctuation symbols, and non-ASCII chars
  const segments = text.match(/[A-Za-z]+|[0-9]+|[^\sA-Za-z0-9]/g);
  if (!segments) {
    return Math.ceil(text.length / 4);
  }

  let tokenCount = 0;
  for (const seg of segments) {
    const len = seg.length;
    if (len <= 4) {
      tokenCount += 1;
    } else if (/^[A-Za-z]+$/.test(seg)) {
      // Longer English/identifier words split into ~1 token per 4.5 chars
      tokenCount += Math.ceil(len / 4.5);
    } else if (/^[0-9]+$/.test(seg)) {
      // Numeric runs typically split every 3 digits in BPE tokenizers
      tokenCount += Math.ceil(len / 3);
    } else {
      tokenCount += Math.ceil(len / 3);
    }
  }

  return Math.max(1, tokenCount);
}

function countSchemaProperties(inputSchema: unknown): number {
  if (typeof inputSchema !== 'object' || inputSchema === null || Array.isArray(inputSchema)) {
    return 0;
  }
  const props = (inputSchema as Record<string, unknown>).properties;
  if (typeof props !== 'object' || props === null || Array.isArray(props)) {
    return 0;
  }
  return Object.keys(props).length;
}

/**
 * Computes the estimated context token tax for a single MCP tool definition.
 */
export function estimateToolTokens(tool: McpToolDefinition, index = 0): ToolTokenBreakdown {
  const name = typeof tool.name === 'string' && tool.name.trim().length > 0 ? tool.name : `<unnamed-tool-${index}>`;
  const description = typeof tool.description === 'string' ? tool.description : '';
  const serializedSchema = tool.inputSchema !== undefined ? JSON.stringify(tool.inputSchema) : '{}';

  const nameTokens = estimateTokens(name);
  const descriptionTokens = estimateTokens(description);
  const schemaTokens = estimateTokens(serializedSchema);
  const totalTokens = nameTokens + descriptionTokens + schemaTokens + TOOL_WRAPPER_OVERHEAD_TOKENS;

  return {
    name,
    descriptionTokens,
    schemaTokens,
    totalTokens,
    propertyCount: countSchemaProperties(tool.inputSchema),
  };
}
