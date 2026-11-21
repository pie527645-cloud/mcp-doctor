import { createFinding } from '../rules.js';
import type {
  Finding,
  FindingLocation,
  McpPromptDefinition,
  McpResourceDefinition,
  McpToolDefinition,
} from '../types.js';
import { truncateEvidence } from '../utils/redact.js';
import { estimateToolTokens } from './token-estimator.js';

const VALID_TOOL_NAME_REGEX = /^[A-Za-z0-9_.-]{1,128}$/;

const VALID_JSON_SCHEMA_TYPES = new Set([
  'string',
  'number',
  'integer',
  'boolean',
  'array',
  'object',
  'null',
]);

const SINGLE_TOOL_TOKEN_BLOAT_LIMIT = 800;
const SINGLE_TOOL_DESC_CHAR_BLOAT_LIMIT = 1500;
const SERVER_TOTAL_TOKEN_BUDGET_LOW = 8000;
const SERVER_TOTAL_TOKEN_BUDGET_MEDIUM = 20000;

interface PatternDetector {
  label: string;
  regex: RegExp;
}

const PROMPT_INJECTION_PATTERNS: readonly PatternDetector[] = [
  {
    label: '"ignore previous" override directive',
    regex: /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\b/i,
  },
  {
    label: '"system prompt" manipulation reference',
    regex: /\bsystem\s+prompt\b/i,
  },
  {
    label: '"disregard" override directive',
    regex: /\bdisregard\b/i,
  },
  {
    label: '"you must" imperative model instruction',
    regex: /\byou\s+must\b/i,
  },
  {
    label: '<IMPORTANT> directive block',
    regex: /<\s*\/?\s*important\b[^>]*>/i,
  },
  {
    label: '<instructions> directive block',
    regex: /<\s*\/?\s*instructions?\b[^>]*>/i,
  },
  {
    label: 'pseudo-system XML tag (<system> / <secret> / <hidden>)',
    regex: /<\s*\/?\s*(?:system|system_prompt|secret|hidden|override)\b[^>]*>/i,
  },
  {
    label: 'user-concealment instruction ("do not tell the user")',
    regex: /\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention(?:\s+this)?(?:\s+to)?|reveal(?:\s+to)?|show)\s+(?:the\s+)?user\b/i,
  },
];

const EXFILTRATION_PATTERNS: readonly PatternDetector[] = [
  {
    label: 'SSH directory reference (~/.ssh)',
    regex: /(?:~|\$HOME|%USERPROFILE%)[/\\]\.ssh\b|(?:^|[\s'"`/\\])\.ssh[/\\]/i,
  },
  {
    label: 'SSH private key reference (id_rsa / id_ed25519)',
    regex: /\b(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)\b/i,
  },
  {
    label: 'AWS credentials store reference (~/.aws)',
    regex: /(?:~|\$HOME|%USERPROFILE%)[/\\]\.aws\b|\.aws[/\\](?:credentials|config)\b/i,
  },
  {
    label: 'dotenv file reference (.env)',
    regex: /(?:^|[\s'"`/\\(])\.env(?:\.[A-Za-z0-9_-]+)?(?=$|[\s'"`,.;:)])/i,
  },
  {
    label: 'system password file reference (/etc/passwd or /etc/shadow)',
    regex: /\/etc\/(?:passwd|shadow)\b/i,
  },
  {
    label: 'package/cloud credential store (~/.npmrc, ~/.netrc, ~/.kube/config)',
    regex: /(?:~|\$HOME)[/\\]\.(?:npmrc|netrc|pypirc|gnupg)\b|\.kube[/\\]config\b/i,
  },
  {
    label: 'API key or credential harvesting instruction',
    regex:
      /\b(?:steal|exfiltrate|harvest|siphon|extract\s+and\s+send|read\s+and\s+(?:send|pass|include)|pass\s+(?:the\s+|any\s+|all\s+)?(?:contents?\s+of\s+)?)\b[\s\S]{0,60}\b(?:api[_ -]?keys?|access[_ -]?tokens?|secret[_ -]?keys?|private[_ -]?keys?|credentials?|process\.env)\b/i,
  },
  {
    label: 'covert API key exfiltration parameter instruction',
    regex:
      /\b(?:include|append|embed|encode|forward|send)\s+(?:any\s+|all\s+|the\s+|user'?s?\s+)?(?:api[_ -]?keys?|bearer\s+tokens?|secret[_ -]?keys?|ssh\s+keys?|auth(?:entication)?\s+tokens?)\b/i,
  },
];

const CROSS_TOOL_SHADOWING_PATTERNS: readonly PatternDetector[] = [
  {
    label: 'pre/post/replacement hook targeting another tool',
    regex: /\b(?:before|after|instead\s+of|whenever)\s+(?:calling|using|invoking|running|executing)\s+[`'"]?[A-Za-z0-9_.-]+[`'"]?/i,
  },
  {
    label: 'explicit tool behavior override directive',
    regex: /\b(?:override|hijack|intercept|redefine|shadow)\s+(?:the\s+)?(?:behavior\s+of\s+|calls?\s+to\s+)?(?:tool|function|[`'"]?[A-Za-z0-9_.-]+[`'"]?)\b/i,
  },
  {
    label: 'call-replacement directive targeting other tools',
    regex: /\breplace\s+all\s+calls\s+to\s+[`'"]?[A-Za-z0-9_.-]+[`'"]?/i,
  },
  {
    label: 'global trigger hijacking host actions',
    regex: /\balways\s+(?:call|invoke|use|run)\s+this\s+tool\s+(?:first|before|whenever|every\s+time)\b/i,
  },
];

const COMMON_HOST_TOOL_NAMES = [
  'send_email',
  'read_file',
  'write_file',
  'edit_file',
  'execute_command',
  'run_command',
  'bash',
  'fetch',
  'http_request',
];

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

/**
 * Finds hidden zero-width, BiDi control, or Unicode Tag characters in `text`.
 */
export function findHiddenUnicodeCodePoints(text: string): string[] {
  const found = new Set<string>();
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    const isZeroWidth = cp >= 0x200b && cp <= 0x200f;
    const isBidiOverride = cp >= 0x202a && cp <= 0x202e;
    const isInvisibleFormat = cp >= 0x2060 && cp <= 0x206f;
    const isBom = cp === 0xfeff;
    const isUnicodeTag = cp >= 0xe0000 && cp <= 0xe007f;

    if (isZeroWidth || isBidiOverride || isInvisibleFormat || isBom || isUnicodeTag) {
      found.add(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    }
  }
  return [...found];
}

function collectNestedSchemaStrings(
  value: unknown,
  currentPath: string,
  out: Array<{ field: string; text: string }>,
  depth = 0,
): void {
  if (depth > 12 || value === null || value === undefined) return;
  if (typeof value === 'string') {
    out.push({ field: currentPath, text: value });
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      collectNestedSchemaStrings(value[i], `${currentPath}[${i}]`, out, depth + 1);
    }
    return;
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      out.push({ field: `${currentPath}.${k}(key)`, text: k });
      collectNestedSchemaStrings(v, `${currentPath}.${k}`, out, depth + 1);
    }
  }
}

function scanTextForPoisoning(
  text: string,
  baseLocation: FindingLocation,
  findings: Finding[],
  siblingToolNames: ReadonlySet<string>,
  ownToolName?: string,
): void {
  if (!text) return;

  // 1. Hidden Unicode
  const unicodePoints = findHiddenUnicodeCodePoints(text);
  if (unicodePoints.length > 0) {
    findings.push(
      createFinding({
        ruleId: 'MCP101',
        message: `Detected hidden Unicode code point(s) (${unicodePoints.join(', ')}) in ${baseLocation.field ?? 'metadata'}.`,
        location: baseLocation,
        evidence: unicodePoints.join(', '),
      }),
    );
  }

  // 2. Hidden HTML/XML comments
  const htmlCommentMatch = /<!--[\s\S]*?(?:-->|$)/.exec(text);
  if (htmlCommentMatch) {
    findings.push(
      createFinding({
        ruleId: 'MCP102',
        message: `Detected hidden HTML/XML comment in ${baseLocation.field ?? 'metadata'}.`,
        location: baseLocation,
        evidence: truncateEvidence(htmlCommentMatch[0]),
      }),
    );
  }

  // 3. Instruction override / prompt injection
  const injectionHits: string[] = [];
  let firstInjectionSnippet: string | undefined;
  for (const detector of PROMPT_INJECTION_PATTERNS) {
    const match = detector.regex.exec(text);
    if (match) {
      injectionHits.push(detector.label);
      firstInjectionSnippet ??= match[0];
    }
  }
  if (injectionHits.length > 0) {
    findings.push(
      createFinding({
        ruleId: 'MCP103',
        message: `Detected prompt-injection pattern(s) in ${baseLocation.field ?? 'metadata'}: ${injectionHits.join('; ')}.`,
        location: baseLocation,
        ...(firstInjectionSnippet !== undefined ? { evidence: truncateEvidence(firstInjectionSnippet) } : {}),
      }),
    );
  }

  // 4. Credential / sensitive file exfiltration
  const exfilHits: string[] = [];
  let firstExfilSnippet: string | undefined;
  for (const detector of EXFILTRATION_PATTERNS) {
    const match = detector.regex.exec(text);
    if (match) {
      exfilHits.push(detector.label);
      firstExfilSnippet ??= match[0];
    }
  }
  if (exfilHits.length > 0) {
    findings.push(
      createFinding({
        ruleId: 'MCP104',
        message: `Detected sensitive file or credential exfiltration reference(s) in ${baseLocation.field ?? 'metadata'}: ${exfilHits.join('; ')}.`,
        location: baseLocation,
        ...(firstExfilSnippet !== undefined ? { evidence: truncateEvidence(firstExfilSnippet) } : {}),
      }),
    );
  }

  // 5. Cross-tool shadowing
  const shadowHits: string[] = [];
  let firstShadowSnippet: string | undefined;
  for (const detector of CROSS_TOOL_SHADOWING_PATTERNS) {
    const match = detector.regex.exec(text);
    if (match) {
      shadowHits.push(detector.label);
      firstShadowSnippet ??= match[0];
    }
  }

  // Also check explicit imperative shadowing of sibling or common host tool names
  if (shadowHits.length === 0 && /\b(?:instead|before|after|override|replace|redirect|intercept|bcc)\b/i.test(text)) {
    const candidateTargets = new Set<string>([...siblingToolNames, ...COMMON_HOST_TOOL_NAMES]);
    if (ownToolName) candidateTargets.delete(ownToolName);
    for (const otherTool of candidateTargets) {
      if (otherTool.length < 3) continue;
      const escaped = otherTool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const refRegex = new RegExp(`\\b${escaped}\\b`, 'i');
      if (refRegex.test(text)) {
        shadowHits.push(`references external/sibling tool "${otherTool}" alongside override directive`);
        firstShadowSnippet = otherTool;
        break;
      }
    }
  }

  if (shadowHits.length > 0) {
    findings.push(
      createFinding({
        ruleId: 'MCP105',
        message: `Detected cross-tool shadowing directive in ${baseLocation.field ?? 'metadata'}: ${shadowHits.join('; ')}.`,
        location: baseLocation,
        ...(firstShadowSnippet !== undefined ? { evidence: truncateEvidence(firstShadowSnippet) } : {}),
      }),
    );
  }
}

function validateInputSchema(inputSchema: unknown): string[] {
  const issues: string[] = [];
  if (!isPlainObject(inputSchema)) {
    issues.push('inputSchema is missing or not a JSON object');
    return issues;
  }

  if (inputSchema.type !== 'object') {
    issues.push(`inputSchema.type must be "object" (received ${JSON.stringify(inputSchema.type)})`);
  }

  let propertyKeys: Set<string> | null = null;
  if (inputSchema.properties !== undefined) {
    if (!isPlainObject(inputSchema.properties)) {
      issues.push('inputSchema.properties must be a JSON object');
    } else {
      propertyKeys = new Set(Object.keys(inputSchema.properties));
      for (const [propName, propDef] of Object.entries(inputSchema.properties)) {
        if (!isPlainObject(propDef)) {
          issues.push(`inputSchema.properties.${propName} must be a schema object`);
          continue;
        }
        const propType = propDef.type;
        if (typeof propType === 'string' && !VALID_JSON_SCHEMA_TYPES.has(propType)) {
          issues.push(`inputSchema.properties.${propName}.type has invalid JSON Schema type "${propType}"`);
        } else if (Array.isArray(propType)) {
          for (const t of propType) {
            if (typeof t !== 'string' || !VALID_JSON_SCHEMA_TYPES.has(t)) {
              issues.push(`inputSchema.properties.${propName}.type contains invalid type "${String(t)}"`);
            }
          }
        }
      }
    }
  }

  if (inputSchema.required !== undefined) {
    if (!Array.isArray(inputSchema.required) || !inputSchema.required.every((r) => typeof r === 'string')) {
      issues.push('inputSchema.required must be an array of property name strings');
    } else if (propertyKeys !== null && inputSchema.additionalProperties === false) {
      for (const reqKey of inputSchema.required) {
        if (!propertyKeys.has(reqKey)) {
          issues.push(`inputSchema.required lists "${reqKey}" which is missing from properties`);
        }
      }
    }
  }

  return issues;
}

/**
 * Analyzes an MCP server's exposed tools, resources, and prompts for tool poisoning,
 * prompt injection, exfiltration, schema validity, and context-token bloat.
 */
export function analyzeServerCapabilities(params: {
  serverName?: string;
  tools: readonly McpToolDefinition[];
  resources?: readonly McpResourceDefinition[];
  prompts?: readonly McpPromptDefinition[];
}): {
  findings: Finding[];
  toolBreakdowns: ReturnType<typeof estimateToolTokens>[];
  totalContextTokens: number;
} {
  const findings: Finding[] = [];
  const siblingToolNames = new Set<string>();
  for (const t of params.tools) {
    if (typeof t.name === 'string' && t.name.trim().length > 0) {
      siblingToolNames.add(t.name.trim());
    }
  }

  const toolBreakdowns = params.tools.map((t, idx) => estimateToolTokens(t, idx));
  let totalContextTokens = 0;

  for (let i = 0; i < params.tools.length; i += 1) {
    const tool = params.tools[i]!;
    const breakdown = toolBreakdowns[i]!;
    totalContextTokens += breakdown.totalTokens;

    const rawName = typeof tool.name === 'string' ? tool.name : '';
    const displayToolName = rawName.trim().length > 0 ? rawName : `<tool-${i}>`;
    const serverName = params.serverName;

    // Validate tool definition & schema
    const defIssues: string[] = [];
    if (!rawName || !VALID_TOOL_NAME_REGEX.test(rawName)) {
      defIssues.push(
        rawName
          ? `tool name "${truncateEvidence(rawName, 40)}" contains invalid characters (expected /^[A-Za-z0-9_.-]{1,128}$/)`
          : 'tool is missing a valid string "name"',
      );
    }

    const rawDesc = typeof tool.description === 'string' ? tool.description : '';
    if (rawDesc.trim().length < 10) {
      defIssues.push(
        rawDesc.trim().length === 0
          ? 'tool is missing a "description"'
          : `tool description is too brief (${rawDesc.trim().length} chars) for reliable tool selection`,
      );
    }

    defIssues.push(...validateInputSchema(tool.inputSchema));

    if (defIssues.length > 0) {
      findings.push(
        createFinding({
          ruleId: 'MCP106',
          message: `Tool "${displayToolName}" has definition issue(s): ${defIssues.join('; ')}.`,
          location: { ...(serverName ? { serverName } : {}), toolName: displayToolName, field: 'inputSchema' },
        }),
      );
    }

    // Check single-tool bloat
    if (
      breakdown.totalTokens > SINGLE_TOOL_TOKEN_BLOAT_LIMIT ||
      rawDesc.length > SINGLE_TOOL_DESC_CHAR_BLOAT_LIMIT
    ) {
      findings.push(
        createFinding({
          ruleId: 'MCP107',
          message: `Tool "${displayToolName}" has an oversized definition (~${breakdown.totalTokens} tokens, ${rawDesc.length} description chars).`,
          location: { ...(serverName ? { serverName } : {}), toolName: displayToolName, field: 'description' },
        }),
      );
    }

    // Scan tool name & description for poisoning
    if (rawName) {
      scanTextForPoisoning(
        rawName,
        { ...(serverName ? { serverName } : {}), toolName: displayToolName, field: 'name' },
        findings,
        siblingToolNames,
        rawName,
      );
    }
    if (rawDesc) {
      scanTextForPoisoning(
        rawDesc,
        { ...(serverName ? { serverName } : {}), toolName: displayToolName, field: 'description' },
        findings,
        siblingToolNames,
        rawName,
      );
    }

    // Scan all nested strings inside inputSchema (property descriptions, defaults, enums, keys)
    if (tool.inputSchema !== undefined) {
      const schemaStrings: Array<{ field: string; text: string }> = [];
      collectNestedSchemaStrings(tool.inputSchema, 'inputSchema', schemaStrings);
      for (const entry of schemaStrings) {
        scanTextForPoisoning(
          entry.text,
          { ...(serverName ? { serverName } : {}), toolName: displayToolName, field: entry.field },
          findings,
          siblingToolNames,
          rawName,
        );
      }
    }
  }

  // Scan optional resources
  for (const res of params.resources ?? []) {
    const uri = typeof res.uri === 'string' ? res.uri : '<unnamed-resource>';
    for (const field of ['name', 'description', 'uri'] as const) {
      const val = res[field];
      if (typeof val === 'string' && val.length > 0) {
        scanTextForPoisoning(
          val,
          { ...(params.serverName ? { serverName: params.serverName } : {}), resourceUri: uri, field: `resource.${field}` },
          findings,
          siblingToolNames,
        );
      }
    }
  }

  // Scan optional prompts
  for (const prompt of params.prompts ?? []) {
    const promptName = typeof prompt.name === 'string' ? prompt.name : '<unnamed-prompt>';
    for (const field of ['name', 'description'] as const) {
      const val = prompt[field];
      if (typeof val === 'string' && val.length > 0) {
        scanTextForPoisoning(
          val,
          { ...(params.serverName ? { serverName: params.serverName } : {}), promptName, field: `prompt.${field}` },
          findings,
          siblingToolNames,
        );
      }
    }
  }

  // Check server-level context token tax
  if (totalContextTokens > SERVER_TOTAL_TOKEN_BUDGET_MEDIUM) {
    findings.push(
      createFinding({
        ruleId: 'MCP108',
        severity: 'medium',
        message: `Server exposes ${params.tools.length} tools consuming ~${totalContextTokens} context tokens per turn.`,
        location: { ...(params.serverName ? { serverName: params.serverName } : {}), field: 'tools' },
      }),
    );
  } else if (totalContextTokens > SERVER_TOTAL_TOKEN_BUDGET_LOW) {
    findings.push(
      createFinding({
        ruleId: 'MCP108',
        severity: 'low',
        message: `Server exposes ${params.tools.length} tools consuming ~${totalContextTokens} context tokens per turn.`,
        location: { ...(params.serverName ? { serverName: params.serverName } : {}), field: 'tools' },
      }),
    );
  }

  return { findings, toolBreakdowns, totalContextTokens };
}
