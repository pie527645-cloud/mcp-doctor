import { formatReport } from './formatters/index.js';
import { inspectServer } from './inspectors/mcp-client.js';
import { scanConfigs } from './scanners/config-scanner.js';
import {
  type AuditReport,
  CliUsageError,
  hasFailingFindings,
  InspectionTargetError,
  type OutputFormat,
  PACKAGE_VERSION,
  type Severity,
} from './types.js';

const VALID_FORMATS = new Set<OutputFormat>(['pretty', 'json', 'markdown', 'sarif']);
const VALID_SEVERITIES = new Set<Severity>(['critical', 'high', 'medium', 'low']);

/** Parsed CLI invocation arguments. */
export interface ParsedCliArgs {
  command: 'scan' | 'inspect' | 'help' | 'version';
  paths: string[];
  stdio?: string;
  url?: string;
  timeoutMs: number;
  format: OutputFormat;
  failOn: Severity;
}

/** Returns the CLI `--help` usage guide. */
export function getHelpText(): string {
  return `mcp-doctor v${PACKAGE_VERSION}
Security, Prompt-Injection, Tool-Poisoning, Config & Context-Tax Auditor for MCP

Usage:
  mcp-doctor scan [paths...] [options]
  mcp-doctor inspect (--stdio "<cmd>" | --url "<http-url>") [options]

Commands:
  scan [paths...]     Scan MCP config files/directories, or auto-discover standard
                      configs (Claude Desktop, Cursor, VS Code, Antigravity, .mcp.json).
  inspect             Connect to a live MCP server via JSON-RPC 2.0 to audit tools,
                      detect prompt injection/poisoning, and measure Context Token Tax.

Inspect Target Flags:
  --stdio "<cmd>"     Spawn stdio MCP command safely (quote-aware argv, shell: false)
  --url "<http-url>"  Connect to HTTP/HTTPS JSON-RPC / Streamable HTTP MCP endpoint
  --timeout <ms>      Maximum connection/inspection timeout in milliseconds (default: 10000)

Global Options:
  --format <fmt>      Output format: pretty | json | markdown | sarif (default: pretty)
  --fail-on <level>   Exit 1 if findings >= level: critical | high | medium | low (default: high)
  -h, --help          Display this help message
  -v, --version       Display version number

Exit Codes:
  0  Clean (no findings meeting or exceeding --fail-on threshold)
  1  Audit failed (one or more findings >= --fail-on threshold)
  2  Invalid CLI arguments, missing config path, or unreachable MCP server`;
}

function consumeFlagValue(argv: readonly string[], index: number, flagName: string): { value: string; nextIndex: number } {
  const current = argv[index]!;
  const eqIdx = current.indexOf('=');
  if (eqIdx >= 0) {
    const val = current.slice(eqIdx + 1);
    if (!val) {
      throw new CliUsageError(`Missing value for ${flagName}.`);
    }
    return { value: val, nextIndex: index };
  }

  const next = argv[index + 1];
  if (next === undefined || (next.startsWith('-') && next !== '-')) {
    throw new CliUsageError(`Missing value for ${flagName}.`);
  }
  return { value: next, nextIndex: index + 1 };
}

/**
 * Parses raw `process.argv.slice(2)` arguments into validated options, throwing `CliUsageError` on invalid input.
 */
export function parseCliArgs(argv: readonly string[]): ParsedCliArgs {
  if (argv.length === 0) {
    return {
      command: 'help',
      paths: [],
      timeoutMs: 10_000,
      format: 'pretty',
      failOn: 'high',
    };
  }

  const first = argv[0]!;
  if (first === '-h' || first === '--help' || first === 'help') {
    return { command: 'help', paths: [], timeoutMs: 10_000, format: 'pretty', failOn: 'high' };
  }
  if (first === '-v' || first === '--version' || first === 'version') {
    return { command: 'version', paths: [], timeoutMs: 10_000, format: 'pretty', failOn: 'high' };
  }

  if (first !== 'scan' && first !== 'inspect') {
    throw new CliUsageError(`Unknown command "${first}". Expected "scan" or "inspect".`);
  }

  const command = first;
  const paths: string[] = [];
  let stdio: string | undefined;
  let url: string | undefined;
  let timeoutMs = 10_000;
  let format: OutputFormat = 'pretty';
  let failOn: Severity = 'high';

  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i]!;

    if (arg === '-h' || arg === '--help') {
      return { command: 'help', paths: [], timeoutMs: 10_000, format: 'pretty', failOn: 'high' };
    }

    if (arg === '--format' || arg.startsWith('--format=')) {
      const consumed = consumeFlagValue(argv, i, '--format');
      i = consumed.nextIndex;
      if (!VALID_FORMATS.has(consumed.value as OutputFormat)) {
        throw new CliUsageError(
          `Invalid --format "${consumed.value}". Expected one of: pretty, json, markdown, sarif.`,
        );
      }
      format = consumed.value as OutputFormat;
      continue;
    }

    if (arg === '--fail-on' || arg.startsWith('--fail-on=')) {
      const consumed = consumeFlagValue(argv, i, '--fail-on');
      i = consumed.nextIndex;
      if (!VALID_SEVERITIES.has(consumed.value as Severity)) {
        throw new CliUsageError(
          `Invalid --fail-on "${consumed.value}". Expected one of: critical, high, medium, low.`,
        );
      }
      failOn = consumed.value as Severity;
      continue;
    }

    if (arg === '--stdio' || arg.startsWith('--stdio=')) {
      if (command !== 'inspect') {
        throw new CliUsageError('Flag --stdio is only valid with the "inspect" command.');
      }
      const consumed = consumeFlagValue(argv, i, '--stdio');
      i = consumed.nextIndex;
      stdio = consumed.value;
      continue;
    }

    if (arg === '--url' || arg.startsWith('--url=')) {
      if (command !== 'inspect') {
        throw new CliUsageError('Flag --url is only valid with the "inspect" command.');
      }
      const consumed = consumeFlagValue(argv, i, '--url');
      i = consumed.nextIndex;
      url = consumed.value;
      continue;
    }

    if (arg === '--timeout' || arg.startsWith('--timeout=')) {
      if (command !== 'inspect') {
        throw new CliUsageError('Flag --timeout is only valid with the "inspect" command.');
      }
      const consumed = consumeFlagValue(argv, i, '--timeout');
      i = consumed.nextIndex;
      if (!/^\d+$/.test(consumed.value)) {
        throw new CliUsageError(`Invalid --timeout "${consumed.value}". Must be a positive integer in milliseconds.`);
      }
      const parsedTimeout = Number.parseInt(consumed.value, 10);
      if (!Number.isSafeInteger(parsedTimeout) || parsedTimeout <= 0) {
        throw new CliUsageError(`Invalid --timeout "${consumed.value}". Must be greater than 0.`);
      }
      timeoutMs = parsedTimeout;
      continue;
    }

    if (arg.startsWith('-')) {
      throw new CliUsageError(`Unknown option "${arg}". Run "mcp-doctor --help" for usage.`);
    }

    if (command === 'scan') {
      paths.push(arg);
    } else {
      throw new CliUsageError(`Unexpected positional argument "${arg}" for "inspect". Use --stdio or --url.`);
    }
  }

  if (command === 'inspect') {
    if ((stdio !== undefined && url !== undefined) || (stdio === undefined && url === undefined)) {
      throw new CliUsageError('Command "inspect" requires exactly one of --stdio "<cmd>" or --url "<http-url>".');
    }
  }

  return {
    command,
    paths,
    ...(stdio !== undefined ? { stdio } : {}),
    ...(url !== undefined ? { url } : {}),
    timeoutMs,
    format,
    failOn,
  };
}

/** Custom I/O streams injectable for programmatic CLI testing. */
export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

const defaultIo: CliIo = {
  stdout: (text) => process.stdout.write(`${text}\n`),
  stderr: (text) => process.stderr.write(`${text}\n`),
};

/**
 * Executes the CLI with `argv` (excluding `node` and script path) and returns the exit code (`0 | 1 | 2`).
 */
export async function runCli(argv: readonly string[], io: CliIo = defaultIo): Promise<number> {
  let parsed: ParsedCliArgs;
  try {
    parsed = parseCliArgs(argv);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    io.stderr(`Error: ${message}`);
    return 2;
  }

  if (parsed.command === 'help') {
    io.stdout(getHelpText());
    return 0;
  }

  if (parsed.command === 'version') {
    io.stdout(PACKAGE_VERSION);
    return 0;
  }

  let report: AuditReport;
  try {
    if (parsed.command === 'scan') {
      report = await scanConfigs({ paths: parsed.paths });
    } else {
      report = await inspectServer({
        stdio: parsed.stdio,
        url: parsed.url,
        timeoutMs: parsed.timeoutMs,
      });
    }
  } catch (err) {
    if (err instanceof CliUsageError || err instanceof InspectionTargetError) {
      io.stderr(`Error: ${err.message}`);
      return 2;
    }
    const message = err instanceof Error ? err.message : String(err);
    io.stderr(`Unexpected error: ${message}`);
    return 2;
  }

  const formatted = formatReport(report, parsed.format);
  io.stdout(formatted);

  return hasFailingFindings(report.findings, parsed.failOn) ? 1 : 0;
}
