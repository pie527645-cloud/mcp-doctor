import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { RULES } from '../rules.js';
import type { AuditReport, Finding, OutputFormat, Severity } from '../types.js';

/** SARIF 2.1.0 top-level document structure. */
export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          help: { text: string; markdown: string };
          defaultConfiguration: { level: 'error' | 'warning' | 'note' };
          properties: {
            tags: string[];
            'security-severity': string;
          };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number; startColumn?: number };
        };
        logicalLocations?: Array<{ name: string; kind: string }>;
      }>;
      properties: Record<string, string>;
    }>;
  }>;
}

function formatLocationLabel(finding: Finding): string {
  const parts: string[] = [];
  if (finding.location.filePath) {
    parts.push(
      finding.location.line !== undefined
        ? `${finding.location.filePath}:${finding.location.line}`
        : finding.location.filePath,
    );
  }
  if (finding.location.serverName) {
    parts.push(`server=${finding.location.serverName}`);
  }
  if (finding.location.toolName) {
    parts.push(`tool=${finding.location.toolName}`);
  }
  if (finding.location.resourceUri) {
    parts.push(`resource=${finding.location.resourceUri}`);
  }
  if (finding.location.promptName) {
    parts.push(`prompt=${finding.location.promptName}`);
  }
  if (finding.location.field) {
    parts.push(`field=${finding.location.field}`);
  }
  return parts.length > 0 ? parts.join(' | ') : 'global';
}

function mapSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
  }
}

function mapSecuritySeverityScore(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '9.5';
    case 'high':
      return '7.8';
    case 'medium':
      return '5.5';
    case 'low':
      return '3.0';
  }
}

function resolveSarifUri(finding: Finding, report: AuditReport): string {
  if (finding.location.filePath) {
    const resolved = path.resolve(finding.location.filePath);
    const rel = path.relative(process.cwd(), resolved);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
      return rel.replace(/\\/g, '/');
    }
    return pathToFileURL(resolved).href;
  }

  const rawTarget = finding.location.serverName ?? report.inspection?.serverInfo?.name ?? 'live-mcp-target';
  const safeSlug = rawTarget.replace(/[^A-Za-z0-9_.-]+/g, '_').replace(/^_+|_+$/g, '') || 'target';
  return `mcp-inspect/${safeSlug}.json`;
}

/**
 * Builds a valid SARIF 2.1.0 object from an `AuditReport` (compatible with GitHub Code Scanning).
 */
export function buildSarifLog(report: AuditReport): SarifLog {
  const orderedRules = Object.values(RULES);
  const ruleIndexMap = new Map<string, number>();
  orderedRules.forEach((r, idx) => ruleIndexMap.set(r.id, idx));

  const sarifRules = orderedRules.map((rule) => ({
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.shortDescription },
    fullDescription: { text: rule.fullDescription },
    help: {
      text: rule.remediation,
      markdown: `**Remediation:** ${rule.remediation}`,
    },
    defaultConfiguration: {
      level: mapSarifLevel(rule.defaultSeverity),
    },
    properties: {
      tags: ['security', 'mcp', rule.category],
      'security-severity': mapSecuritySeverityScore(rule.defaultSeverity),
    },
  }));

  const results = report.findings.map((finding) => {
    const ruleIndex = ruleIndexMap.get(finding.ruleId) ?? 0;
    const logicalName =
      finding.location.toolName ??
      finding.location.promptName ??
      finding.location.resourceUri ??
      finding.location.serverName;
    const logicalKind = finding.location.toolName ? 'function' : 'module';

    return {
      ruleId: finding.ruleId,
      ruleIndex,
      level: mapSarifLevel(finding.severity),
      message: {
        text: finding.evidence ? `${finding.message} (Evidence: ${finding.evidence})` : finding.message,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: resolveSarifUri(finding, report),
            },
            region: {
              startLine: finding.location.line ?? 1,
              ...(finding.location.column !== undefined ? { startColumn: finding.location.column } : {}),
            },
          },
          ...(logicalName
            ? {
                logicalLocations: [{ name: logicalName, kind: logicalKind }],
              }
            : {}),
        },
      ],
      properties: {
        severity: finding.severity,
        category: finding.category,
        ...(finding.evidence !== undefined ? { evidence: finding.evidence } : {}),
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-doctor',
            version: report.version,
            informationUri: 'https://github.com/pie527645-cloud/mcp-doctor',
            rules: sarifRules,
          },
        },
        results,
      },
    ],
  };
}

/**
 * Formats an `AuditReport` as human-readable terminal text.
 */
export function formatPretty(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`mcp-doctor v${report.version} — ${report.mode === 'scan' ? 'Configuration Security Scan' : 'Live MCP Server Inspection'}`);
  lines.push('='.repeat(72));

  if (report.mode === 'scan') {
    const files = report.scannedFiles ?? [];
    if (files.length === 0) {
      lines.push('No MCP configuration files were found in default discovery locations.');
      if (report.checkedDefaultPaths && report.checkedDefaultPaths.length > 0) {
        lines.push(`Checked ${report.checkedDefaultPaths.length} standard paths.`);
      }
    } else {
      lines.push(`Scanned Config Files (${files.length}):`);
      for (const f of files) {
        const status = f.parsed ? `${f.serverCount} server(s)` : 'MALFORMED JSON';
        lines.push(`  - ${f.filePath} [${status}]`);
      }
    }
  }

  if (report.inspection) {
    const info = report.inspection;
    const serverTitle = info.serverInfo?.name
      ? `${info.serverInfo.name}${info.serverInfo.version ? ` v${info.serverInfo.version}` : ''}`
      : info.target;
    lines.push(`Target:             ${info.target} (${info.transport})`);
    lines.push(`Server:             ${serverTitle}`);
    lines.push(`Protocol Version:   ${info.protocolVersion ?? 'unknown'}`);
    lines.push(`Handshake Latency:  ${info.handshakeLatencyMs} ms (total session: ${info.totalLatencyMs} ms)`);
    lines.push(`Capabilities:       ${info.toolCount} tool(s), ${info.resourceCount} resource(s), ${info.promptCount} prompt(s)`);
    lines.push(`Context Token Tax:  ~${info.totalContextTokens} tokens/turn`);

    if (info.tools.length > 0) {
      lines.push('');
      lines.push('Per-Tool Context Token Tax:');
      for (const t of info.tools) {
        const paddedName = t.name.padEnd(28, ' ');
        lines.push(
          `  - ${paddedName} ~${String(t.totalTokens).padStart(4, ' ')} tokens (desc: ${t.descriptionTokens}, schema: ${t.schemaTokens}, props: ${t.propertyCount})`,
        );
      }
    }
  }

  lines.push('');
  if (report.findings.length === 0) {
    lines.push('Findings: 0 issues detected.');
  } else {
    lines.push(
      `Findings (${report.summary.total} total — critical: ${report.summary.critical}, high: ${report.summary.high}, medium: ${report.summary.medium}, low: ${report.summary.low}):`,
    );
    for (const finding of report.findings) {
      const badge = `[${finding.severity.toUpperCase()}]`.padEnd(10, ' ');
      lines.push(`  ${badge} ${finding.ruleId} — ${finding.message}`);
      lines.push(`             Location: ${formatLocationLabel(finding)}`);
      if (finding.evidence) {
        lines.push(`             Evidence: ${finding.evidence}`);
      }
      if (finding.remediation) {
        lines.push(`             Fix:      ${finding.remediation}`);
      }
    }
  }

  return lines.join('\n');
}

/**
 * Formats an `AuditReport` as GitHub-Flavored Markdown.
 */
export function formatMarkdown(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`# mcp-doctor ${report.mode === 'scan' ? 'Config Scan' : 'Server Inspection'} Report`);
  lines.push('');
  lines.push(
    `**Summary:** ${report.summary.total} finding(s) — Critical: **${report.summary.critical}**, High: **${report.summary.high}**, Medium: **${report.summary.medium}**, Low: **${report.summary.low}**`,
  );
  lines.push('');

  if (report.mode === 'scan' && report.scannedFiles) {
    lines.push('## Scanned Configuration Files');
    lines.push('');
    if (report.scannedFiles.length === 0) {
      lines.push('_No MCP configuration files discovered._');
    } else {
      lines.push('| File | Parsed | Servers |');
      lines.push('| :--- | :--- | ---: |');
      for (const f of report.scannedFiles) {
        lines.push(`| \`${f.filePath}\` | ${f.parsed ? 'Yes' : 'No'} | ${f.serverCount} |`);
      }
    }
    lines.push('');
  }

  if (report.inspection) {
    const info = report.inspection;
    lines.push('## Server & Context Token Tax');
    lines.push('');
    lines.push(`- **Target:** \`${info.target}\` (\`${info.transport}\`)`);
    if (info.serverInfo?.name) {
      lines.push(`- **Server Info:** \`${info.serverInfo.name}\` ${info.serverInfo.version ? `(\`${info.serverInfo.version}\`)` : ''}`);
    }
    lines.push(`- **Handshake Latency:** ${info.handshakeLatencyMs} ms`);
    lines.push(`- **Total Context Token Tax:** ~${info.totalContextTokens} tokens (${info.toolCount} tools)`);
    lines.push('');

    if (info.tools.length > 0) {
      lines.push('| Tool | Total Tokens | Description Tokens | Schema Tokens | Properties |');
      lines.push('| :--- | ---: | ---: | ---: | ---: |');
      for (const t of info.tools) {
        lines.push(`| \`${t.name}\` | ${t.totalTokens} | ${t.descriptionTokens} | ${t.schemaTokens} | ${t.propertyCount} |`);
      }
      lines.push('');
    }
  }

  lines.push('## Security & Quality Findings');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('No security or configuration issues detected.');
  } else {
    lines.push('| Severity | Rule | Location | Message |');
    lines.push('| :--- | :--- | :--- | :--- |');
    for (const f of report.findings) {
      const safeMsg = f.message.replace(/\|/g, '\\|');
      const safeLoc = formatLocationLabel(f).replace(/\|/g, '\\|');
      lines.push(`| **${f.severity.toUpperCase()}** | \`${f.ruleId}\` | \`${safeLoc}\` | ${safeMsg} |`);
    }
  }

  return lines.join('\n');
}

/**
 * Serializes an `AuditReport` into the requested `OutputFormat`.
 */
export function formatReport(report: AuditReport, format: OutputFormat): string {
  switch (format) {
    case 'pretty':
      return formatPretty(report);
    case 'json':
      return JSON.stringify(report, null, 2);
    case 'markdown':
      return formatMarkdown(report);
    case 'sarif':
      return JSON.stringify(buildSarifLog(report), null, 2);
  }
}
