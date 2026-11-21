/**
 * Core types, error classes, and severity helpers for mcp-doctor.
 */

export const PACKAGE_VERSION = '1.0.0';

/** Finding severity levels ordered from highest to lowest impact. */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Output formats supported by the CLI and formatters. */
export type OutputFormat = 'pretty' | 'json' | 'markdown' | 'sarif';

/** Numeric ranking used to compare severities against `--fail-on` thresholds. */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** High-level classification category for security and quality findings. */
export type FindingCategory =
  | 'secrets'
  | 'supply-chain'
  | 'command-injection'
  | 'transport-security'
  | 'config-syntax'
  | 'tool-poisoning'
  | 'prompt-injection'
  | 'exfiltration'
  | 'tool-shadowing'
  | 'schema-quality'
  | 'context-tax';

/** Structured location metadata pointing to a config entry or live MCP tool field. */
export interface FindingLocation {
  filePath?: string;
  serverName?: string;
  toolName?: string;
  resourceUri?: string;
  promptName?: string;
  field?: string;
  line?: number;
  column?: number;
}

/** A single security, configuration, or quality finding emitted by an audit. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  message: string;
  location: FindingLocation;
  evidence?: string;
  remediation?: string;
}

/** Static rule descriptor used for consistent findings and SARIF 2.1.0 driver metadata. */
export interface RuleMetadata {
  id: string;
  name: string;
  shortDescription: string;
  fullDescription: string;
  defaultSeverity: Severity;
  category: FindingCategory;
  remediation: string;
}

/** Per-tool estimated context token consumption breakdown. */
export interface ToolTokenBreakdown {
  name: string;
  descriptionTokens: number;
  schemaTokens: number;
  totalTokens: number;
  propertyCount: number;
}

/** Metadata about a scanned MCP configuration file. */
export interface ScannedConfigFile {
  filePath: string;
  exists: boolean;
  parsed: boolean;
  serverCount: number;
  servers: string[];
}

/** Raw MCP tool definition returned by `tools/list`. */
export interface McpToolDefinition {
  name?: unknown;
  description?: unknown;
  inputSchema?: unknown;
  annotations?: unknown;
  [key: string]: unknown;
}

/** Raw MCP resource definition returned by `resources/list`. */
export interface McpResourceDefinition {
  uri?: unknown;
  name?: unknown;
  description?: unknown;
  mimeType?: unknown;
  [key: string]: unknown;
}

/** Raw MCP prompt definition returned by `prompts/list`. */
export interface McpPromptDefinition {
  name?: unknown;
  description?: unknown;
  arguments?: unknown;
  [key: string]: unknown;
}

/** Live MCP server metrics gathered during `inspect`. */
export interface InspectionMetrics {
  target: string;
  transport: 'stdio' | 'http';
  serverInfo?: {
    name?: string;
    version?: string;
  };
  protocolVersion?: string;
  handshakeLatencyMs: number;
  totalLatencyMs: number;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
  totalContextTokens: number;
  tools: ToolTokenBreakdown[];
}

/** Aggregated severity counts for an audit report. */
export interface FindingSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/** Complete structured output produced by `scanConfigs` or `inspectServer`. */
export interface AuditReport {
  mode: 'scan' | 'inspect';
  timestamp: string;
  version: string;
  scannedFiles?: ScannedConfigFile[];
  checkedDefaultPaths?: string[];
  inspection?: InspectionMetrics;
  findings: Finding[];
  summary: FindingSummary;
}

/** Error thrown when CLI arguments or options are invalid (maps to exit code 2). */
export class CliUsageError extends Error {
  public readonly exitCode = 2;

  constructor(message: string) {
    super(message);
    this.name = 'CliUsageError';
  }
}

/** Error thrown when a target config path or MCP server cannot be reached (maps to exit code 2). */
export class InspectionTargetError extends Error {
  public readonly exitCode = 2;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'InspectionTargetError';
  }
}

/** Returns true if `severity` is greater than or equal to `threshold`. */
export function meetsSeverityThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

/** Returns true if any finding in `findings` meets or exceeds `threshold`. */
export function hasFailingFindings(findings: readonly Finding[], threshold: Severity): boolean {
  return findings.some((f) => meetsSeverityThreshold(f.severity, threshold));
}

/** Sorts findings deterministically by severity (descending), then ruleId, then location. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const rankDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (rankDiff !== 0) return rankDiff;
    const ruleCmp = a.ruleId.localeCompare(b.ruleId);
    if (ruleCmp !== 0) return ruleCmp;
    const locA = `${a.location.filePath ?? ''}:${a.location.serverName ?? ''}:${a.location.toolName ?? ''}`;
    const locB = `${b.location.filePath ?? ''}:${b.location.serverName ?? ''}:${b.location.toolName ?? ''}`;
    return locA.localeCompare(locB);
  });
}

/** Computes severity count totals for a list of findings. */
export function summarizeFindings(findings: readonly Finding[]): FindingSummary {
  const summary: FindingSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: findings.length,
  };
  for (const f of findings) {
    summary[f.severity] += 1;
  }
  return summary;
}
