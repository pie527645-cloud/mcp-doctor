/**
 * Programmatic API for `mcp-doctor`:
 * MCP Security, Prompt-Injection, Tool-Poisoning, Configuration & Context-Tax Auditor.
 */

export {
  PACKAGE_VERSION,
  SEVERITY_RANK,
  CliUsageError,
  InspectionTargetError,
  meetsSeverityThreshold,
  hasFailingFindings,
  sortFindings,
  summarizeFindings,
  type Severity,
  type OutputFormat,
  type FindingCategory,
  type FindingLocation,
  type Finding,
  type RuleMetadata,
  type ToolTokenBreakdown,
  type ScannedConfigFile,
  type McpToolDefinition,
  type McpResourceDefinition,
  type McpPromptDefinition,
  type InspectionMetrics,
  type FindingSummary,
  type AuditReport,
} from './types.js';

export { RULES, getRule, createFinding } from './rules.js';

export { tokenizeCommand, type TokenizedCommand } from './utils/argv-tokenizer.js';
export { redactSecret, truncateEvidence, calculateShannonEntropy } from './utils/redact.js';
export {
  isCloudMetadataOrLinkLocalIp,
  isPrivateOrLoopbackIp,
  isLoopbackHost,
  assertSafeHttpInspectionUrl,
} from './utils/url-security.js';

export {
  scanStringForSecrets,
  scanKeyValueForSecrets,
  scanArgsForSecrets,
  isPlaceholderOrInterpolation,
  type SecretMatch,
} from './scanners/secrets.js';

export {
  getStandardConfigPaths,
  isInsecureRemoteUrl,
  scanConfigContent,
  scanConfigFile,
  scanConfigs,
  type ScanOptions,
} from './scanners/config-scanner.js';

export { estimateTokens, estimateToolTokens } from './inspectors/token-estimator.js';
export { analyzeServerCapabilities, findHiddenUnicodeCodePoints } from './inspectors/tool-analyzer.js';
export { inspectServer, parseSseJsonRpcResponse, type InspectOptions } from './inspectors/mcp-client.js';

export {
  buildSarifLog,
  formatPretty,
  formatMarkdown,
  formatReport,
  type SarifLog,
} from './formatters/index.js';

export { parseCliArgs, runCli, getHelpText, type ParsedCliArgs, type CliIo } from './cli.js';
