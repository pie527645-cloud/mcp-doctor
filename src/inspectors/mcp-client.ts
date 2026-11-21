import { spawn, type ChildProcess } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { createFinding } from '../rules.js';
import { isInsecureRemoteUrl } from '../scanners/config-scanner.js';
import {
  type AuditReport,
  CliUsageError,
  type Finding,
  InspectionTargetError,
  type McpPromptDefinition,
  type McpResourceDefinition,
  type McpToolDefinition,
  PACKAGE_VERSION,
  sortFindings,
  summarizeFindings,
} from '../types.js';
import { tokenizeCommand } from '../utils/argv-tokenizer.js';
import { truncateEvidence } from '../utils/redact.js';
import { assertSafeHttpInspectionUrl } from '../utils/url-security.js';
import { analyzeServerCapabilities } from './tool-analyzer.js';

const MCP_PROTOCOL_VERSION = '2024-11-05';
const MAX_LINE_BYTES = 10 * 1024 * 1024;
const MAX_STDERR_CAPTURE = 4096;
const MAX_PAGINATION_PAGES = 10;

/** Options for live MCP server inspection via stdio or Streamable HTTP. */
export interface InspectOptions {
  /** Command line string to launch a local stdio MCP server (`spawn(..., { shell: false })`). */
  stdio?: string;
  /** HTTP/HTTPS URL of a remote or local Streamable HTTP JSON-RPC MCP endpoint. */
  url?: string;
  /** Maximum timeout in milliseconds for the inspection session (default: `10000`). */
  timeoutMs?: number;
  /** Optional custom environment variables when spawning a stdio child process. */
  env?: NodeJS.ProcessEnv;
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: number | string | null;
  result?: Record<string, unknown>;
  error?: {
    code?: number;
    message?: string;
    data?: unknown;
  };
}

class JsonRpcMethodError extends Error {
  public readonly code: number | undefined;

  constructor(message: string, code?: number) {
    super(message);
    this.name = 'JsonRpcMethodError';
    this.code = code;
  }
}

interface RawSessionResult {
  serverInfo?: { name?: string; version?: string };
  protocolVersion?: string;
  handshakeLatencyMs: number;
  totalLatencyMs: number;
  tools: McpToolDefinition[];
  resources: McpResourceDefinition[];
  prompts: McpPromptDefinition[];
}

async function terminateChildCleanly(child: ChildProcess): Promise<void> {
  try {
    child.stdin?.end();
  } catch {
    // Ignore stream close errors
  }

  if (child.exitCode === null && !child.killed) {
    try {
      child.kill('SIGTERM');
    } catch {
      // Ignore kill errors if process already exited
    }

    await new Promise<void>((resolve) => {
      const killTimer = setTimeout(() => {
        if (child.exitCode === null) {
          try {
            child.kill('SIGKILL');
          } catch {
            // Ignore
          }
        }
        resolve();
      }, 250);
      killTimer.unref?.();

      child.once('close', () => {
        clearTimeout(killTimer);
        resolve();
      });
      child.once('exit', () => {
        clearTimeout(killTimer);
        resolve();
      });
    });
  }

  child.stdout?.destroy();
  child.stderr?.destroy();
  child.stdin?.destroy();
}

async function inspectViaStdio(
  commandLine: string,
  timeoutMs: number,
  customEnv?: NodeJS.ProcessEnv,
): Promise<RawSessionResult> {
  const { command, args } = tokenizeCommand(commandLine);
  const startAll = performance.now();
  const deadline = Date.now() + timeoutMs;

  let child: ChildProcess;
  try {
    child = spawn(command, args, {
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: customEnv ?? process.env,
      windowsHide: true,
    });
  } catch (err) {
    throw new InspectionTargetError(
      `Failed to spawn stdio MCP command "${command}": ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }

  let stderrTail = '';
  let stdoutBuffer = '';
  let spawnError: Error | null = null;
  let closedCode: number | null = null;
  let isClosed = false;

  const pending = new Map<
    number,
    {
      resolve: (res: Record<string, unknown>) => void;
      reject: (err: Error) => void;
    }
  >();

  function rejectAllPending(err: Error): void {
    for (const entry of pending.values()) {
      entry.reject(err);
    }
    pending.clear();
  }

  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (chunk: string) => {
    stderrTail = (stderrTail + chunk).slice(-MAX_STDERR_CAPTURE);
  });

  child.on('error', (err) => {
    spawnError = err;
    rejectAllPending(
      new InspectionTargetError(`Failed to execute stdio MCP server "${command}": ${err.message}`, { cause: err }),
    );
  });

  child.on('close', (code) => {
    isClosed = true;
    closedCode = code;
    const suffix = stderrTail.trim() ? ` (stderr: ${truncateEvidence(stderrTail.trim(), 200)})` : '';
    rejectAllPending(
      new InspectionTargetError(`MCP stdio process exited prematurely with code ${String(code)}${suffix}`),
    );
  });

  child.stdout?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => {
    stdoutBuffer += chunk;
    if (stdoutBuffer.length > MAX_LINE_BYTES) {
      rejectAllPending(new InspectionTargetError('MCP stdio response exceeded maximum buffer size (10 MB).'));
      stdoutBuffer = '';
      return;
    }

    let newlineIdx = stdoutBuffer.indexOf('\n');
    while (newlineIdx >= 0) {
      const rawLine = stdoutBuffer.slice(0, newlineIdx).trim();
      stdoutBuffer = stdoutBuffer.slice(newlineIdx + 1);
      newlineIdx = stdoutBuffer.indexOf('\n');

      if (!rawLine) continue;
      let parsed: JsonRpcResponse;
      try {
        parsed = JSON.parse(rawLine) as JsonRpcResponse;
      } catch {
        // Ignore non-JSON diagnostic lines if any precede protocol frames, or continue waiting
        continue;
      }

      if (typeof parsed.id === 'number' && pending.has(parsed.id)) {
        const waiter = pending.get(parsed.id)!;
        pending.delete(parsed.id);
        if (parsed.error) {
          waiter.reject(new JsonRpcMethodError(parsed.error.message ?? 'JSON-RPC error', parsed.error.code));
        } else {
          waiter.resolve(parsed.result ?? {});
        }
      }
    }
  });

  let nextId = 1;

  function sendNotification(method: string, params?: Record<string, unknown>): void {
    const payload: JsonRpcRequest = {
      jsonrpc: '2.0',
      method,
      ...(params ? { params } : {}),
    };
    child.stdin?.write(`${JSON.stringify(payload)}\n`);
  }

  function sendRequest(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      return Promise.reject(new InspectionTargetError(`Timed out after ${timeoutMs}ms inspecting stdio MCP server.`));
    }
    if (spawnError) {
      return Promise.reject(
        new InspectionTargetError(`Failed to execute stdio MCP server "${command}": ${spawnError.message}`, {
          cause: spawnError,
        }),
      );
    }
    if (isClosed) {
      const suffix = stderrTail.trim() ? ` (stderr: ${truncateEvidence(stderrTail.trim(), 200)})` : '';
      return Promise.reject(
        new InspectionTargetError(`MCP stdio process exited prematurely with code ${String(closedCode)}${suffix}`),
      );
    }

    const id = nextId++;
    const payload: JsonRpcRequest = {
      jsonrpc: '2.0',
      id,
      method,
      ...(params ? { params } : {}),
    };

    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new InspectionTargetError(`Timed out after ${timeoutMs}ms waiting for "${method}" response.`));
      }, remaining);

      pending.set(id, {
        resolve: (res) => {
          clearTimeout(timer);
          resolve(res);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });

      child.stdin?.write(`${JSON.stringify(payload)}\n`, (writeErr) => {
        if (writeErr) {
          clearTimeout(timer);
          pending.delete(id);
          reject(
            new InspectionTargetError(`Failed writing "${method}" request to stdio server: ${writeErr.message}`, {
              cause: writeErr,
            }),
          );
        }
      });
    });
  }

  try {
    const initStart = performance.now();
    const initResult = await sendRequest('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'mcp-doctor', version: PACKAGE_VERSION },
    });
    const handshakeLatencyMs = Math.max(1, Math.round(performance.now() - initStart));

    sendNotification('notifications/initialized');

    const tools = await collectPaginatedItems<McpToolDefinition>(
      (cursor) => sendRequest('tools/list', cursor ? { cursor } : {}),
      'tools',
      true,
    );

    const resources = await collectPaginatedItems<McpResourceDefinition>(
      (cursor) => sendRequest('resources/list', cursor ? { cursor } : {}),
      'resources',
      false,
    );

    const prompts = await collectPaginatedItems<McpPromptDefinition>(
      (cursor) => sendRequest('prompts/list', cursor ? { cursor } : {}),
      'prompts',
      false,
    );

    const totalLatencyMs = Math.max(handshakeLatencyMs, Math.round(performance.now() - startAll));
    const rawServerInfo = initResult.serverInfo as Record<string, unknown> | undefined;

    return {
      ...(rawServerInfo
        ? {
            serverInfo: {
              ...(typeof rawServerInfo.name === 'string' ? { name: rawServerInfo.name } : {}),
              ...(typeof rawServerInfo.version === 'string' ? { version: rawServerInfo.version } : {}),
            },
          }
        : {}),
      ...(typeof initResult.protocolVersion === 'string' ? { protocolVersion: initResult.protocolVersion } : {}),
      handshakeLatencyMs,
      totalLatencyMs,
      tools,
      resources,
      prompts,
    };
  } finally {
    await terminateChildCleanly(child);
  }
}

/**
 * Parses an `text/event-stream` (SSE) body and returns the JSON-RPC response matching `expectedId`.
 */
export function parseSseJsonRpcResponse(sseBody: string, expectedId: number): JsonRpcResponse | null {
  const normalized = sseBody.replace(/\r\n/g, '\n');
  const blocks = normalized.split('\n\n');
  let fallbackResponse: JsonRpcResponse | null = null;

  for (const block of blocks) {
    const lines = block.split('\n');
    const dataLines: string[] = [];
    for (const line of lines) {
      if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trimStart());
      }
    }
    if (dataLines.length === 0) continue;

    const payload = dataLines.join('\n').trim();
    if (!payload) continue;

    try {
      const parsed = JSON.parse(payload) as JsonRpcResponse | JsonRpcResponse[];
      const candidates = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of candidates) {
        if (item.id === expectedId) {
          return item;
        }
        if (fallbackResponse === null && (item.result !== undefined || item.error !== undefined)) {
          fallbackResponse = item;
        }
      }
    } catch {
      // Ignore non-JSON SSE events (such as endpoint announcements)
    }
  }

  return fallbackResponse;
}

async function readResponseTextBounded(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) {
    return '';
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let totalBytes = 0;
  let output = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        totalBytes += value.byteLength;
        if (totalBytes > maxBytes) {
          await reader.cancel();
          throw new InspectionTargetError(`HTTP MCP response exceeded maximum size limit (${maxBytes} bytes).`);
        }
        output += decoder.decode(value, { stream: true });
      }
    }
    output += decoder.decode();
    return output;
  } finally {
    reader.releaseLock();
  }
}

async function fetchWithSafeRedirects(
  initialUrl: URL,
  init: RequestInit,
  deadline: number,
  timeoutMs: number,
): Promise<Response> {
  let currentUrl = initialUrl;
  await assertSafeHttpInspectionUrl(currentUrl);

  for (let hop = 0; hop <= 3; hop += 1) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new InspectionTargetError(`Timed out after ${timeoutMs}ms connecting to "${currentUrl.href}".`);
    }

    let response: Response;
    try {
      response = await fetch(currentUrl, {
        ...init,
        redirect: 'manual',
        signal: AbortSignal.timeout(remaining),
      });
    } catch (err) {
      const isTimeout = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
      if (isTimeout) {
        throw new InspectionTargetError(`Timed out after ${timeoutMs}ms connecting to "${currentUrl.href}".`, {
          cause: err,
        });
      }
      throw new InspectionTargetError(
        `Failed connecting to HTTP MCP endpoint "${currentUrl.href}": ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      await response.body?.cancel().catch(() => undefined);
      if (!location) {
        throw new InspectionTargetError(
          `HTTP MCP endpoint "${currentUrl.href}" returned redirect HTTP ${response.status} without Location header.`,
        );
      }
      if (hop === 3) {
        throw new InspectionTargetError(`HTTP MCP endpoint "${initialUrl.href}" exceeded maximum redirect hops (3).`);
      }
      let nextUrl: URL;
      try {
        nextUrl = new URL(location, currentUrl);
      } catch (err) {
        throw new InspectionTargetError(`Invalid redirect Location "${location}" from "${currentUrl.href}".`, {
          cause: err,
        });
      }
      await assertSafeHttpInspectionUrl(nextUrl, currentUrl);
      currentUrl = nextUrl;
      continue;
    }

    return response;
  }

  throw new InspectionTargetError(`HTTP MCP endpoint "${initialUrl.href}" exceeded redirect limit.`);
}

async function inspectViaHttp(rawUrl: string, timeoutMs: number): Promise<RawSessionResult> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw new CliUsageError(`Invalid --url "${rawUrl}": must be a valid http:// or https:// URL.`);
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new CliUsageError(
      `Unsupported URL protocol "${parsedUrl.protocol}" in --url: only http:// and https:// are supported.`,
    );
  }

  const startAll = performance.now();
  const deadline = Date.now() + timeoutMs;
  let nextId = 1;
  let sessionId: string | null = null;

  async function postJsonRpc(
    method: string,
    params?: Record<string, unknown>,
    isNotification = false,
  ): Promise<Record<string, unknown>> {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new InspectionTargetError(`Timed out after ${timeoutMs}ms inspecting HTTP MCP endpoint "${rawUrl}".`);
    }

    const id = isNotification ? undefined : nextId++;
    const bodyObj: JsonRpcRequest = {
      jsonrpc: '2.0',
      ...(id !== undefined ? { id } : {}),
      method,
      ...(params ? { params } : {}),
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    };
    if (sessionId) {
      headers['Mcp-Session-Id'] = sessionId;
    }

    const response = await fetchWithSafeRedirects(
      parsedUrl,
      {
        method: 'POST',
        headers,
        body: JSON.stringify(bodyObj),
      },
      deadline,
      timeoutMs,
    );

    const returnedSession = response.headers.get('mcp-session-id');
    if (returnedSession) {
      sessionId = returnedSession;
    }

    if (isNotification) {
      await response.body?.cancel().catch(() => undefined);
      return {};
    }

    if (!response.ok) {
      const errBody = await readResponseTextBounded(response, 4096).catch(() => '');
      throw new InspectionTargetError(
        `HTTP MCP endpoint "${rawUrl}" returned HTTP ${response.status} for "${method}"${
          errBody ? `: ${truncateEvidence(errBody, 160)}` : ''
        }`,
      );
    }

    const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
    const rawBody = await readResponseTextBounded(response, MAX_LINE_BYTES);

    let rpcResp: JsonRpcResponse | null = null;
    if (contentType.includes('text/event-stream') || rawBody.trimStart().startsWith('event:') || rawBody.trimStart().startsWith('data:')) {
      rpcResp = parseSseJsonRpcResponse(rawBody, id!);
    } else {
      try {
        const parsedJson = JSON.parse(rawBody) as JsonRpcResponse | JsonRpcResponse[];
        if (Array.isArray(parsedJson)) {
          rpcResp = parsedJson.find((item) => item.id === id) ?? parsedJson[0] ?? null;
        } else {
          rpcResp = parsedJson;
        }
      } catch (err) {
        throw new InspectionTargetError(
          `HTTP MCP endpoint "${rawUrl}" returned malformed JSON for "${method}": ${truncateEvidence(rawBody, 120)}`,
          { cause: err },
        );
      }
    }

    if (!rpcResp) {
      throw new InspectionTargetError(`HTTP MCP endpoint "${rawUrl}" returned no JSON-RPC response for "${method}".`);
    }

    if (rpcResp.error) {
      throw new JsonRpcMethodError(rpcResp.error.message ?? 'JSON-RPC error', rpcResp.error.code);
    }

    return rpcResp.result ?? {};
  }

  const initStart = performance.now();
  const initResult = await postJsonRpc('initialize', {
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'mcp-doctor', version: PACKAGE_VERSION },
  });
  const handshakeLatencyMs = Math.max(1, Math.round(performance.now() - initStart));

  await postJsonRpc('notifications/initialized', undefined, true).catch(() => ({}));

  const tools = await collectPaginatedItems<McpToolDefinition>(
    (cursor) => postJsonRpc('tools/list', cursor ? { cursor } : {}),
    'tools',
    true,
  );

  const resources = await collectPaginatedItems<McpResourceDefinition>(
    (cursor) => postJsonRpc('resources/list', cursor ? { cursor } : {}),
    'resources',
    false,
  );

  const prompts = await collectPaginatedItems<McpPromptDefinition>(
    (cursor) => postJsonRpc('prompts/list', cursor ? { cursor } : {}),
    'prompts',
    false,
  );

  const totalLatencyMs = Math.max(handshakeLatencyMs, Math.round(performance.now() - startAll));
  const rawServerInfo = initResult.serverInfo as Record<string, unknown> | undefined;

  return {
    ...(rawServerInfo
      ? {
          serverInfo: {
            ...(typeof rawServerInfo.name === 'string' ? { name: rawServerInfo.name } : {}),
            ...(typeof rawServerInfo.version === 'string' ? { version: rawServerInfo.version } : {}),
          },
        }
      : {}),
    ...(typeof initResult.protocolVersion === 'string' ? { protocolVersion: initResult.protocolVersion } : {}),
    handshakeLatencyMs,
    totalLatencyMs,
    tools,
    resources,
    prompts,
  };
}

async function collectPaginatedItems<T>(
  fetchPage: (cursor?: string) => Promise<Record<string, unknown>>,
  arrayKey: string,
  requiredCapability: boolean,
): Promise<T[]> {
  const collected: T[] = [];
  let cursor: string | undefined;

  for (let page = 0; page < MAX_PAGINATION_PAGES; page += 1) {
    let result: Record<string, unknown>;
    try {
      result = await fetchPage(cursor);
    } catch (err) {
      // Method not found (-32601) or optional capability unsupported -> return gracefully
      if (err instanceof JsonRpcMethodError) {
        if (!requiredCapability || err.code === -32601) {
          return collected;
        }
        throw new InspectionTargetError(`MCP server returned JSON-RPC error on "${arrayKey}/list": ${err.message}`, {
          cause: err,
        });
      }
      if (!requiredCapability) {
        return collected;
      }
      throw err;
    }

    const pageItems = result[arrayKey];
    if (Array.isArray(pageItems)) {
      collected.push(...(pageItems as T[]));
    }

    const nextCursor = result.nextCursor;
    if (typeof nextCursor === 'string' && nextCursor.length > 0 && nextCursor !== cursor) {
      cursor = nextCursor;
    } else {
      break;
    }
  }

  return collected;
}

/**
 * Connects to a live MCP server over `stdio` or `http`, measures handshake latency
 * and context token tax, and audits all exposed tools, resources, and prompts.
 */
export async function inspectServer(options: InspectOptions): Promise<AuditReport> {
  const hasStdio = options.stdio !== undefined;
  const hasUrl = options.url !== undefined;

  if ((hasStdio && hasUrl) || (!hasStdio && !hasUrl)) {
    throw new CliUsageError('Exactly one of --stdio "<cmd>" or --url "<http-url>" must be specified.');
  }

  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isInteger(timeoutMs)) {
    throw new CliUsageError(`Invalid --timeout "${String(options.timeoutMs)}": must be a positive integer in milliseconds.`);
  }

  const transport = hasStdio ? 'stdio' : 'http';
  const target = (hasStdio ? options.stdio : options.url)!;
  const extraFindings: Finding[] = [];

  if (transport === 'http' && isInsecureRemoteUrl(target)) {
    extraFindings.push(
      createFinding({
        ruleId: 'MCP005',
        message: `Target MCP HTTP endpoint "${target}" uses unencrypted cleartext HTTP on a non-localhost host.`,
        location: { serverName: target, field: 'url' },
        evidence: truncateEvidence(target),
      }),
    );
  }

  const session =
    transport === 'stdio'
      ? await inspectViaStdio(target, timeoutMs, options.env)
      : await inspectViaHttp(target, timeoutMs);

  const serverLabel = session.serverInfo?.name ?? target;
  const analysis = analyzeServerCapabilities({
    serverName: serverLabel,
    tools: session.tools,
    resources: session.resources,
    prompts: session.prompts,
  });

  const sorted = sortFindings([...extraFindings, ...analysis.findings]);

  return {
    mode: 'inspect',
    timestamp: new Date().toISOString(),
    version: PACKAGE_VERSION,
    inspection: {
      target,
      transport,
      ...(session.serverInfo ? { serverInfo: session.serverInfo } : {}),
      ...(session.protocolVersion ? { protocolVersion: session.protocolVersion } : {}),
      handshakeLatencyMs: session.handshakeLatencyMs,
      totalLatencyMs: session.totalLatencyMs,
      toolCount: session.tools.length,
      resourceCount: session.resources.length,
      promptCount: session.prompts.length,
      totalContextTokens: analysis.totalContextTokens,
      tools: analysis.toolBreakdowns,
    },
    findings: sorted,
    summary: summarizeFindings(sorted),
  };
}
