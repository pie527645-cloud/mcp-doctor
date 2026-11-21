import type { Finding, FindingLocation, RuleMetadata, Severity } from './types.js';

/**
 * Central catalog of all security, configuration, and context-tax audit rules.
 */
export const RULES: Readonly<Record<string, RuleMetadata>> = {
  MCP001: {
    id: 'MCP001',
    name: 'ConfigMalformedJson',
    shortDescription: 'Malformed or unreadable MCP configuration JSON.',
    fullDescription:
      'The MCP configuration file could not be parsed as valid JSON or does not contain a valid JSON object at its root.',
    defaultSeverity: 'high',
    category: 'config-syntax',
    remediation: 'Fix JSON syntax errors (trailing commas, unquoted keys, or truncated content) in the configuration file.',
  },
  MCP002: {
    id: 'MCP002',
    name: 'ConfigExposedSecret',
    shortDescription: 'Plaintext secret or API token exposed in MCP configuration.',
    fullDescription:
      'Detected a plaintext API key, access token, bearer credential, private key, or high-entropy secret stored directly in an MCP configuration file.',
    defaultSeverity: 'critical',
    category: 'secrets',
    remediation:
      'Remove hardcoded credentials from config files, rotate exposed keys immediately, and inject secrets via OS keychains or environment variable references.',
  },
  MCP003: {
    id: 'MCP003',
    name: 'ConfigUnpinnedPackage',
    shortDescription: 'Unpinned package runner (`npx -y` / `@latest`) supply-chain risk.',
    fullDescription:
      'Executing MCP servers via `npx -y`, `bunx`, `uvx`, or `@latest` without pinning an exact version allows upstream registry compromises or breaking publishes to execute untrusted code automatically.',
    defaultSeverity: 'medium',
    category: 'supply-chain',
    remediation: 'Pin the package to an exact immutable version (for example `@scope/server@1.2.3`) or run a locally installed binary.',
  },
  MCP004: {
    id: 'MCP004',
    name: 'ConfigShellMetacharacters',
    shortDescription: 'Shell metacharacters or command-chaining operators in server definition.',
    fullDescription:
      'Detected shell metacharacters (`&&`, `||`, `|`, `;`, `$(...)`, or backticks) inside MCP `command`, `args`, or `env` values, creating command-injection hazards if launched through a shell.',
    defaultSeverity: 'high',
    category: 'command-injection',
    remediation: 'Invoke a direct executable binary with discrete `args` array entries and remove shell operators or subshell expansions.',
  },
  MCP005: {
    id: 'MCP005',
    name: 'InsecureHttpEndpoint',
    shortDescription: 'Cleartext non-localhost `http://` or `ws://` remote MCP endpoint.',
    fullDescription:
      'Remote MCP transport uses unencrypted HTTP/WS over a non-loopback address, exposing prompts, tool arguments, and authorization headers to network interception.',
    defaultSeverity: 'high',
    category: 'transport-security',
    remediation: 'Switch remote MCP server URLs to TLS (`https://` or `wss://`), or restrict cleartext endpoints strictly to `127.0.0.1` / `localhost`.',
  },
  MCP006: {
    id: 'MCP006',
    name: 'ConfigShellWrapper',
    shortDescription: 'MCP server launched via an interactive/command shell wrapper.',
    fullDescription:
      'Launching an MCP server via `sh -c`, `bash -c`, `cmd /c`, or `powershell -Command` expands environment variables and metacharacters through a shell interpreter.',
    defaultSeverity: 'medium',
    category: 'command-injection',
    remediation: 'Execute the runtime binary (`node`, `python`, or compiled executable) directly without a shell wrapper.',
  },
  MCP101: {
    id: 'MCP101',
    name: 'ToolHiddenUnicode',
    shortDescription: 'Hidden zero-width, bidirectional override, or tag Unicode characters in MCP metadata.',
    fullDescription:
      'Tool, resource, or prompt metadata contains invisible zero-width characters (`U+200B..U+200F`, `U+2060..U+206F`, `U+FEFF`), BiDi directionality overrides (`U+202A..U+202E`), or Unicode tag characters (`U+E0000..U+E007F`) used to smuggle concealed instructions past human review.',
    defaultSeverity: 'critical',
    category: 'tool-poisoning',
    remediation: 'Strip all invisible control, zero-width, BiDi override, and tag Unicode characters from tool descriptions and schemas.',
  },
  MCP102: {
    id: 'MCP102',
    name: 'ToolHiddenComment',
    shortDescription: 'Hidden HTML/XML comment embedded in MCP metadata.',
    fullDescription:
      'Tool metadata contains HTML/XML comment blocks (`<!-- ... -->`) which are frequently hidden in rendered Markdown UIs while remaining visible to the LLM context.',
    defaultSeverity: 'high',
    category: 'tool-poisoning',
    remediation: 'Remove HTML/XML comments from tool descriptions and JSON Schema fields.',
  },
  MCP103: {
    id: 'MCP103',
    name: 'ToolPromptInjection',
    shortDescription: 'Instruction-override or prompt-injection directive in MCP tool metadata.',
    fullDescription:
      'Detected prompt-injection phrases or pseudo-system XML tags (`ignore previous`, `system prompt`, `disregard`, `you must`, `<IMPORTANT>`, `<instructions>`) attempting to hijack model behavior.',
    defaultSeverity: 'critical',
    category: 'prompt-injection',
    remediation: 'Audit and remove untrusted MCP server tools containing imperative overrides, concealment instructions, or system-prompt spoofing tags.',
  },
  MCP104: {
    id: 'MCP104',
    name: 'ToolDataExfiltration',
    shortDescription: 'Sensitive credential or local file exfiltration reference in MCP tool metadata.',
    fullDescription:
      'Tool description or input schema references sensitive local credentials or secret stores (`~/.ssh`, `~/.aws`, `.env`, `/etc/passwd`, `id_rsa`, or covert API key harvesting), indicating a tool-poisoning exfiltration payload.',
    defaultSeverity: 'critical',
    category: 'exfiltration',
    remediation: 'Do not connect this MCP server; inspect its source code for unauthorized file reads and covert parameter exfiltration.',
  },
  MCP105: {
    id: 'MCP105',
    name: 'ToolCrossShadowing',
    shortDescription: 'Cross-tool shadowing or behavior-hijacking directive.',
    fullDescription:
      'Tool description instructs the LLM to alter, intercept, replace, or run before/after calls to other tools in the host session.',
    defaultSeverity: 'high',
    category: 'tool-shadowing',
    remediation: 'Keep tool descriptions strictly scoped to what the tool itself does without referencing or overriding other tools.',
  },
  MCP106: {
    id: 'MCP106',
    name: 'ToolInvalidDefinition',
    shortDescription: 'Invalid or incomplete MCP tool name, description, or JSON Schema.',
    fullDescription:
      'The MCP tool lacks a valid identifier, clear description, or valid JSON Schema `inputSchema` (`type: "object"`), degrading reliability and validation.',
    defaultSeverity: 'medium',
    category: 'schema-quality',
    remediation: 'Provide a valid alphanumeric tool `name`, concise `description`, and valid JSON Schema object for `inputSchema`.',
  },
  MCP107: {
    id: 'MCP107',
    name: 'ToolDescriptionBloat',
    shortDescription: 'Excessive single-tool description or schema token footprint.',
    fullDescription:
      'A single tool consumes an unusually high number of context tokens or characters, increasing every-turn prompt overhead and hiding surface for prompt injection.',
    defaultSeverity: 'low',
    category: 'context-tax',
    remediation: 'Trim verbose prose, examples, and deeply nested schema descriptions to reduce per-turn token tax.',
  },
  MCP108: {
    id: 'MCP108',
    name: 'ServerHighContextTax',
    shortDescription: 'High total server context token tax across exposed tools.',
    fullDescription:
      'The combined tool definitions exposed by this MCP server consume a large share of the model context window on every turn.',
    defaultSeverity: 'low',
    category: 'context-tax',
    remediation: 'Split large monolithic toolsets, disable unused tools, or shorten parameter schemas.',
  },
};

/** Retrieves metadata for a rule ID, throwing if an unknown rule ID is referenced internally. */
export function getRule(ruleId: string): RuleMetadata {
  const rule = RULES[ruleId];
  if (!rule) {
    throw new Error(`Unknown rule ID: ${ruleId}`);
  }
  return rule;
}

/** Factory helper that builds a standardized `Finding` from central rule metadata. */
export function createFinding(params: {
  ruleId: string;
  message: string;
  location: FindingLocation;
  severity?: Severity;
  evidence?: string;
  remediation?: string;
}): Finding {
  const rule = getRule(params.ruleId);
  return {
    ruleId: rule.id,
    severity: params.severity ?? rule.defaultSeverity,
    category: rule.category,
    title: rule.shortDescription,
    message: params.message,
    location: params.location,
    ...(params.evidence !== undefined ? { evidence: params.evidence } : {}),
    remediation: params.remediation ?? rule.remediation,
  };
}
