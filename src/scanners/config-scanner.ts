import { existsSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createFinding } from '../rules.js';
import {
  type AuditReport,
  type Finding,
  InspectionTargetError,
  PACKAGE_VERSION,
  type ScannedConfigFile,
  sortFindings,
  summarizeFindings,
} from '../types.js';
import { truncateEvidence } from '../utils/redact.js';
import { scanArgsForSecrets, scanKeyValueForSecrets, scanStringForSecrets } from './secrets.js';

const STANDARD_CONFIG_FILENAMES = new Set([
  '.mcp.json',
  'mcp.json',
  'claude_desktop_config.json',
  'mcp_config.json',
]);

const IGNORED_JSON_FILENAMES = new Set([
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'tsconfig.build.json',
  'jsconfig.json',
  'biome.json',
  'renovate.json',
]);

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next']);

const PATH_LIST_ENV_KEYS = new Set([
  'PATH',
  'PATHEXT',
  'NODE_PATH',
  'PYTHONPATH',
  'CLASSPATH',
  'PSMODULEPATH',
  'LD_LIBRARY_PATH',
  'DYLD_LIBRARY_PATH',
]);

const PACKAGE_RUNNERS = new Set(['npx', 'npx.cmd', 'bunx', 'bunx.exe', 'uvx', 'uvx.exe', 'pipx']);

const SHELL_BINARIES = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
]);

/** Options for `scanConfigs`. */
export interface ScanOptions {
  /** Explicit file or directory paths to scan. When empty/omitted, auto-discovers standard MCP configs. */
  paths?: string[];
  /** Working directory used for project-level config auto-discovery (defaults to `process.cwd()`). */
  cwd?: string;
  /** Home directory used for user-level config auto-discovery (defaults to `os.homedir()`). */
  homedir?: string;
}

/**
 * Returns candidate standard MCP configuration paths across Claude Desktop, Cursor,
 * VS Code, Antigravity, Windsurf, and project-local directories.
 */
export function getStandardConfigPaths(
  cwd = process.cwd(),
  homedir = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const candidates: string[] = [
    path.resolve(cwd, '.mcp.json'),
    path.resolve(cwd, 'mcp.json'),
    path.resolve(cwd, '.vscode', 'mcp.json'),
    path.resolve(cwd, '.cursor', 'mcp.json'),
  ];

  const appData = env.APPDATA ?? path.join(homedir, 'AppData', 'Roaming');
  const xdgConfig = env.XDG_CONFIG_HOME ?? path.join(homedir, '.config');

  // Claude Desktop (Windows, macOS, Linux)
  candidates.push(path.join(appData, 'Claude', 'claude_desktop_config.json'));
  candidates.push(path.join(homedir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  candidates.push(path.join(xdgConfig, 'Claude', 'claude_desktop_config.json'));

  // Claude Code & Cursor
  candidates.push(path.join(homedir, '.claude.json'));
  candidates.push(path.join(homedir, '.claude', 'mcp.json'));
  candidates.push(path.join(homedir, '.cursor', 'mcp.json'));

  // VS Code User MCP configs
  candidates.push(path.join(appData, 'Code', 'User', 'mcp.json'));
  candidates.push(path.join(homedir, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'));
  candidates.push(path.join(xdgConfig, 'Code', 'User', 'mcp.json'));

  // Antigravity & Windsurf
  candidates.push(path.join(homedir, '.gemini', 'antigravity', 'mcp_config.json'));
  candidates.push(path.join(homedir, '.gemini', 'settings.json'));
  candidates.push(path.join(homedir, '.codeium', 'windsurf', 'mcp_config.json'));

  // Deduplicate normalized paths
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const candidate of candidates) {
    const normalized = path.normalize(candidate);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      unique.push(normalized);
    }
  }
  return unique;
}

async function collectDirectoryConfigs(dirPath: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(currentDir: string, depth: number): Promise<void> {
    if (depth > 5) return;
    const entries = await readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(fullPath, depth + 1);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        const lower = entry.name.toLowerCase();
        if (IGNORED_JSON_FILENAMES.has(lower) || lower.endsWith('.sarif.json')) {
          continue;
        }
        const parentName = path.basename(currentDir).toLowerCase();
        const isKnownMcpPath =
          STANDARD_CONFIG_FILENAMES.has(lower) ||
          lower.endsWith('.mcp.json') ||
          (lower === 'mcp.json' && (parentName === '.vscode' || parentName === '.cursor' || parentName === '.claude'));

        // Include standard MCP config paths anywhere in tree, or direct .json files in explicitly targeted directories
        if (isKnownMcpPath || depth === 0) {
          found.push(fullPath);
        }
      }
    }
  }

  await walk(dirPath, 0);
  return found.sort();
}

function findLineNumber(rawText: string, needle: string): number | undefined {
  if (!needle) return undefined;
  const idx = rawText.indexOf(needle);
  if (idx < 0) return undefined;
  let line = 1;
  for (let i = 0; i < idx; i += 1) {
    if (rawText.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function parseJsonSyntaxErrorPosition(rawText: string, err: unknown): { line?: number; column?: number } {
  const msg = err instanceof Error ? err.message : String(err);
  const lineColMatch = /line\s+(\d+)\s+column\s+(\d+)/i.exec(msg);
  if (lineColMatch) {
    return {
      line: Number.parseInt(lineColMatch[1]!, 10),
      column: Number.parseInt(lineColMatch[2]!, 10),
    };
  }

  const posMatch = /position\s+(\d+)/i.exec(msg);
  if (posMatch) {
    const pos = Number.parseInt(posMatch[1]!, 10);
    if (!Number.isNaN(pos) && pos >= 0 && pos <= rawText.length) {
      let line = 1;
      let col = 1;
      for (let i = 0; i < pos; i += 1) {
        if (rawText.charCodeAt(i) === 10) {
          line += 1;
          col = 1;
        } else {
          col += 1;
        }
      }
      return { line, column: col };
    }
  }

  return {};
}

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

/**
 * Checks whether a URL uses insecure cleartext `http:` or `ws:` over a non-loopback host.
 */
export function isInsecureRemoteUrl(rawUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'ws:') {
    return false;
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host === '::1' || host === '127.0.0.1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    return false;
  }

  return true;
}

function detectShellMetacharacters(value: string, allowSemicolon = false): string | null {
  if (/\$\([^)]*\)/.test(value)) return '$(...) subshell expansion';
  if (/`[^`]*`/.test(value)) return 'backtick command substitution';
  if (/&&/.test(value)) return '&& command chaining';
  if (/\|\|/.test(value)) return '|| conditional command chaining';
  if (/\|/.test(value)) return '| pipe operator';
  if (!allowSemicolon && /;/.test(value)) return '; command separator';
  if (/[\r\n]/.test(value)) return 'newline injection';
  return null;
}

function extractRunnerInfo(
  command: string,
  args: readonly string[],
): { runner: string; autoConfirm: boolean; packageSpec?: string } | null {
  const base = path.basename(command).toLowerCase();
  let runner: string | null = null;
  let startIdx = 0;

  if (PACKAGE_RUNNERS.has(base)) {
    runner = base.replace(/\.(?:cmd|exe)$/, '');
  } else if ((base === 'pnpm' || base === 'pnpm.cmd') && args[0] === 'dlx') {
    runner = 'pnpm dlx';
    startIdx = 1;
  } else if ((base === 'npm' || base === 'npm.cmd') && args[0] === 'exec') {
    runner = 'npm exec';
    startIdx = 1;
  }

  if (!runner) return null;

  let autoConfirm = runner === 'bunx' || runner === 'pnpm dlx';
  let packageSpec: string | undefined;

  for (let i = startIdx; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === '-y' || arg === '--yes') {
      autoConfirm = true;
      continue;
    }
    if (arg === '-p' || arg === '--package') {
      if (i + 1 < args.length) {
        packageSpec = args[i + 1];
      }
      break;
    }
    if (arg.startsWith('--package=')) {
      packageSpec = arg.slice('--package='.length);
      break;
    }
    if (arg === '--') {
      packageSpec = args[i + 1];
      break;
    }
    if (arg.startsWith('-')) {
      continue;
    }
    packageSpec = arg;
    break;
  }

  return { runner, autoConfirm, ...(packageSpec !== undefined ? { packageSpec } : {}) };
}

function isPinnedPackageSpec(spec: string): { pinned: boolean; isLatest: boolean } {
  const trimmed = spec.trim();
  // Local/file/git specs
  if (trimmed.startsWith('.') || trimmed.startsWith('/') || /^[A-Za-z]:\\/.test(trimmed)) {
    return { pinned: true, isLatest: false };
  }

  // Python uvx / pipx exact pin `pkg==1.2.3`
  if (/^[A-Za-z0-9_.-]+==[0-9]+\.[0-9]+/.test(trimmed)) {
    return { pinned: true, isLatest: false };
  }

  // npm scoped (`@scope/pkg@version`) vs unscoped (`pkg@version`)
  const atIndex = trimmed.lastIndexOf('@');
  if (atIndex <= 0) {
    return { pinned: false, isLatest: false };
  }

  const versionPart = trimmed.slice(atIndex + 1);
  if (versionPart.toLowerCase() === 'latest' || versionPart === '*') {
    return { pinned: false, isLatest: true };
  }

  // Range prefixes (^, ~, >=, >, <) are not immutable exact pins
  if (/^[\^~><=]/.test(versionPart)) {
    return { pinned: false, isLatest: false };
  }

  // Exact semver (with optional v prefix or pre-release/build tag) or sha256 digest
  const isExactSemver = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(versionPart);
  return { pinned: isExactSemver, isLatest: false };
}

function extractServersMap(parsed: Record<string, unknown>): Record<string, unknown> {
  if (isPlainObject(parsed.mcpServers)) {
    return parsed.mcpServers;
  }
  if (isPlainObject(parsed.servers)) {
    return parsed.servers;
  }
  if (isPlainObject(parsed.mcp) && isPlainObject(parsed.mcp.servers)) {
    return parsed.mcp.servers;
  }
  return {};
}

/**
 * Audits raw JSON configuration text from `filePath` and returns findings plus parsed server metadata.
 */
export function scanConfigContent(
  rawText: string,
  filePath: string,
): { fileInfo: ScannedConfigFile; findings: Finding[] } {
  const findings: Finding[] = [];
  let parsedRoot: unknown;

  try {
    parsedRoot = JSON.parse(rawText);
  } catch (err) {
    const pos = parseJsonSyntaxErrorPosition(rawText, err);
    const detail = err instanceof Error ? err.message : String(err);
    findings.push(
      createFinding({
        ruleId: 'MCP001',
        message: `Failed to parse JSON in "${filePath}": ${detail}`,
        location: { filePath, ...pos },
      }),
    );
    return {
      fileInfo: { filePath, exists: true, parsed: false, serverCount: 0, servers: [] },
      findings,
    };
  }

  if (!isPlainObject(parsedRoot)) {
    findings.push(
      createFinding({
        ruleId: 'MCP001',
        message: `Configuration root in "${filePath}" must be a JSON object.`,
        location: { filePath, line: 1, column: 1 },
      }),
    );
    return {
      fileInfo: { filePath, exists: true, parsed: false, serverCount: 0, servers: [] },
      findings,
    };
  }

  const serversMap = extractServersMap(parsedRoot);
  const serverNames = Object.keys(serversMap);

  for (const serverName of serverNames) {
    const serverDef = serversMap[serverName];
    if (!isPlainObject(serverDef)) continue;

    const serverLine = findLineNumber(rawText, `"${serverName}"`);
    const command = typeof serverDef.command === 'string' ? serverDef.command : undefined;
    const args: string[] = Array.isArray(serverDef.args)
      ? serverDef.args.filter((item): item is string => typeof item === 'string')
      : [];

    // 1. Check command secrets, shell wrappers, and metacharacters
    if (command !== undefined) {
      for (const secret of scanStringForSecrets(command)) {
        findings.push(
          createFinding({
            ruleId: 'MCP002',
            message: `Server "${serverName}" exposes ${secret.provider} in "command".`,
            location: { filePath, serverName, field: 'command', line: serverLine },
            evidence: secret.redactedValue,
          }),
        );
      }

      const cmdMeta = detectShellMetacharacters(command);
      if (cmdMeta) {
        findings.push(
          createFinding({
            ruleId: 'MCP004',
            message: `Server "${serverName}" contains ${cmdMeta} in "command".`,
            location: { filePath, serverName, field: 'command', line: serverLine },
            evidence: truncateEvidence(command),
          }),
        );
      }

      const baseCmd = path.basename(command).toLowerCase();
      if (SHELL_BINARIES.has(baseCmd)) {
        const hasExecFlag = args.some((a) => /^-(?:c|lc|command|encodedcommand)$/i.test(a) || /^\/c$/i.test(a));
        if (hasExecFlag) {
          findings.push(
            createFinding({
              ruleId: 'MCP006',
              message: `Server "${serverName}" invokes shell interpreter "${baseCmd}" with inline command execution.`,
              location: { filePath, serverName, field: 'command', line: serverLine },
              evidence: truncateEvidence(`${command} ${args.join(' ')}`),
            }),
          );
        }
      }

      // 2. Check unpinned npx / @latest supply-chain risks
      const runnerInfo = extractRunnerInfo(command, args);
      if (runnerInfo && runnerInfo.packageSpec) {
        const pinState = isPinnedPackageSpec(runnerInfo.packageSpec);
        if (!pinState.pinned) {
          const severity = runnerInfo.autoConfirm || pinState.isLatest ? 'high' : 'medium';
          const reason = pinState.isLatest
            ? `uses mutable "@latest" tag (${runnerInfo.packageSpec})`
            : runnerInfo.autoConfirm
              ? `auto-installs unpinned package "${runnerInfo.packageSpec}" via ${runnerInfo.runner} -y`
              : `executes unpinned package "${runnerInfo.packageSpec}" via ${runnerInfo.runner}`;
          findings.push(
            createFinding({
              ruleId: 'MCP003',
              severity,
              message: `Server "${serverName}" ${reason}.`,
              location: { filePath, serverName, field: 'args', line: serverLine },
              evidence: truncateEvidence(`${command} ${args.join(' ')}`),
            }),
          );
        }
      } else {
        // Even for non-npx commands, flag explicit @latest package references in args
        for (const arg of args) {
          if (/(?:^|[\s=])@?[a-z0-9_.-]+(?:\/[a-z0-9_.-]+)?@latest$/i.test(arg)) {
            findings.push(
              createFinding({
                ruleId: 'MCP003',
                severity: 'medium',
                message: `Server "${serverName}" references mutable "@latest" package tag in "args".`,
                location: { filePath, serverName, field: 'args', line: serverLine },
                evidence: truncateEvidence(arg),
              }),
            );
          }
        }
      }
    }

    // 3. Check args for secrets, shell metacharacters, and cleartext remote URLs
    const argSecrets = scanArgsForSecrets(args);
    for (const secret of argSecrets) {
      findings.push(
        createFinding({
          ruleId: 'MCP002',
          message: `Server "${serverName}" exposes ${secret.provider} in args[${secret.argIndex}].`,
          location: { filePath, serverName, field: `args[${secret.argIndex}]`, line: serverLine },
          evidence: secret.redactedValue,
        }),
      );
    }

    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i]!;
      const argMeta = detectShellMetacharacters(arg);
      if (argMeta) {
        findings.push(
          createFinding({
            ruleId: 'MCP004',
            message: `Server "${serverName}" contains ${argMeta} in args[${i}].`,
            location: { filePath, serverName, field: `args[${i}]`, line: serverLine },
            evidence: truncateEvidence(arg),
          }),
        );
      }

      if (/^(?:http|ws):\/\//i.test(arg) && isInsecureRemoteUrl(arg)) {
        findings.push(
          createFinding({
            ruleId: 'MCP005',
            message: `Server "${serverName}" connects to cleartext remote endpoint in args[${i}].`,
            location: { filePath, serverName, field: `args[${i}]`, line: serverLine },
            evidence: truncateEvidence(arg),
          }),
        );
      }
    }

    // 4. Check env map for secrets and shell metacharacters
    if (isPlainObject(serverDef.env)) {
      for (const [envKey, envVal] of Object.entries(serverDef.env)) {
        if (typeof envVal !== 'string') continue;
        const envLine = findLineNumber(rawText, `"${envKey}"`) ?? serverLine;

        const envSecrets = scanKeyValueForSecrets(envKey, envVal);
        for (const secret of envSecrets) {
          findings.push(
            createFinding({
              ruleId: 'MCP002',
              message: `Server "${serverName}" exposes ${secret.provider} in env.${envKey}.`,
              location: { filePath, serverName, field: `env.${envKey}`, line: envLine },
              evidence: secret.redactedValue,
            }),
          );
        }

        const allowSemicolon = PATH_LIST_ENV_KEYS.has(envKey.toUpperCase());
        const envMeta = detectShellMetacharacters(envVal, allowSemicolon);
        if (envMeta) {
          findings.push(
            createFinding({
              ruleId: 'MCP004',
              message: `Server "${serverName}" contains ${envMeta} in env.${envKey}.`,
              location: { filePath, serverName, field: `env.${envKey}`, line: envLine },
              evidence: truncateEvidence(`${envKey}=${envVal}`),
            }),
          );
        }
      }
    }

    // 5. Check headers map for exposed tokens
    if (isPlainObject(serverDef.headers)) {
      for (const [headerKey, headerVal] of Object.entries(serverDef.headers)) {
        if (typeof headerVal !== 'string') continue;
        const headerLine = findLineNumber(rawText, `"${headerKey}"`) ?? serverLine;
        const headerSecrets = scanKeyValueForSecrets(headerKey, headerVal);
        for (const secret of headerSecrets) {
          findings.push(
            createFinding({
              ruleId: 'MCP002',
              message: `Server "${serverName}" exposes ${secret.provider} in headers.${headerKey}.`,
              location: { filePath, serverName, field: `headers.${headerKey}`, line: headerLine },
              evidence: secret.redactedValue,
            }),
          );
        }
      }
    }

    // 6. Check remote URL fields (`url`, `serverUrl`, `httpUrl`, `endpoint`)
    for (const urlField of ['url', 'serverUrl', 'httpUrl', 'endpoint'] as const) {
      const rawUrl = serverDef[urlField];
      if (typeof rawUrl !== 'string') continue;
      const urlLine = findLineNumber(rawText, rawUrl) ?? serverLine;

      if (isInsecureRemoteUrl(rawUrl)) {
        findings.push(
          createFinding({
            ruleId: 'MCP005',
            message: `Server "${serverName}" uses unencrypted remote endpoint in "${urlField}".`,
            location: { filePath, serverName, field: urlField, line: urlLine },
            evidence: truncateEvidence(rawUrl),
          }),
        );
      }

      const urlSecrets = scanStringForSecrets(rawUrl);
      for (const secret of urlSecrets) {
        findings.push(
          createFinding({
            ruleId: 'MCP002',
            message: `Server "${serverName}" embeds ${secret.provider} in "${urlField}".`,
            location: { filePath, serverName, field: urlField, line: urlLine },
            evidence: secret.redactedValue,
          }),
        );
      }
    }
  }

  return {
    fileInfo: {
      filePath,
      exists: true,
      parsed: true,
      serverCount: serverNames.length,
      servers: serverNames,
    },
    findings,
  };
}

/**
 * Reads and audits a single MCP configuration file on disk.
 */
export async function scanConfigFile(filePath: string): Promise<{ fileInfo: ScannedConfigFile; findings: Finding[] }> {
  const resolved = path.resolve(filePath);
  const rawText = await readFile(resolved, 'utf8');
  return scanConfigContent(rawText, resolved);
}

/**
 * Audits explicit configuration files/directories, or auto-discovers standard MCP configs
 * when `options.paths` is empty or omitted.
 */
export async function scanConfigs(options: ScanOptions = {}): Promise<AuditReport> {
  const explicitPaths = options.paths ?? [];
  const filesToScan: string[] = [];
  let checkedDefaultPaths: string[] | undefined;

  if (explicitPaths.length === 0) {
    checkedDefaultPaths = getStandardConfigPaths(options.cwd, options.homedir);
    for (const candidate of checkedDefaultPaths) {
      if (existsSync(candidate)) {
        filesToScan.push(candidate);
      }
    }
  } else {
    for (const rawTarget of explicitPaths) {
      const resolved = path.resolve(rawTarget);
      let targetStat;
      try {
        targetStat = await stat(resolved);
      } catch (err) {
        throw new InspectionTargetError(`Config path does not exist: ${resolved}`, { cause: err });
      }

      if (targetStat.isFile()) {
        filesToScan.push(resolved);
      } else if (targetStat.isDirectory()) {
        const dirFiles = await collectDirectoryConfigs(resolved);
        filesToScan.push(...dirFiles);
      }
    }
  }

  // Deduplicate target files
  const uniqueFiles = [...new Set(filesToScan)];
  const scannedFiles: ScannedConfigFile[] = [];
  const allFindings: Finding[] = [];

  for (const file of uniqueFiles) {
    const { fileInfo, findings } = await scanConfigFile(file);
    scannedFiles.push(fileInfo);
    allFindings.push(...findings);
  }

  const sorted = sortFindings(allFindings);
  return {
    mode: 'scan',
    timestamp: new Date().toISOString(),
    version: PACKAGE_VERSION,
    scannedFiles,
    ...(checkedDefaultPaths !== undefined ? { checkedDefaultPaths } : {}),
    findings: sorted,
    summary: summarizeFindings(sorted),
  };
}
