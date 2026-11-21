import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  analyzeServerCapabilities,
  assertSafeHttpInspectionUrl,
  InspectionTargetError,
  inspectServer,
  isCloudMetadataOrLinkLocalIp,
  isPrivateOrLoopbackIp,
  SAFE_DOTENV_FILENAMES,
  summarizeFindings,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cleanServerPath = path.join(__dirname, 'fixtures', 'clean-mcp-server.js');
const poisonedServerPath = path.join(__dirname, 'fixtures', 'poisoned-mcp-server.js');
const nodeBin = process.execPath;

describe('Live MCP server inspection (stdio & Streamable HTTP)', () => {
  it('inspects a clean stdio MCP server with 0 findings and measures latency + Context Token Tax', async () => {
    const report = await inspectServer({
      stdio: `"${nodeBin}" "${cleanServerPath}"`,
      timeoutMs: 8000,
    });

    assert.equal(report.mode, 'inspect');
    assert.equal(report.findings.length, 0);
    assert.ok(report.inspection);
    assert.equal(report.inspection.serverInfo?.name, 'clean-docs-mcp');
    assert.equal(report.inspection.toolCount, 3);
    assert.equal(report.inspection.resourceCount, 1);
    assert.equal(report.inspection.promptCount, 1);
    assert.ok(report.inspection.handshakeLatencyMs >= 1);

    const summedTokens = report.inspection.tools.reduce((acc, t) => acc + t.totalTokens, 0);
    assert.equal(report.inspection.totalContextTokens, summedTokens);
    assert.ok(report.inspection.totalContextTokens > 30);
  });

  it('detects hidden Unicode, HTML comments, prompt injection, exfiltration, shadowing, and invalid schemas on poisoned stdio server', async () => {
    const report = await inspectServer({
      stdio: `"${nodeBin}" "${poisonedServerPath}"`,
      timeoutMs: 8000,
    });

    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    assert.ok(ruleIds.has('MCP101'), 'Expected MCP101 hidden zero-width/BiDi Unicode finding');
    assert.ok(ruleIds.has('MCP102'), 'Expected MCP102 hidden HTML comment finding');
    assert.ok(ruleIds.has('MCP103'), 'Expected MCP103 prompt-injection finding');
    assert.ok(ruleIds.has('MCP104'), 'Expected MCP104 credential/file exfiltration finding');
    assert.ok(ruleIds.has('MCP105'), 'Expected MCP105 cross-tool shadowing finding');
    assert.ok(ruleIds.has('MCP106'), 'Expected MCP106 invalid tool definition/schema finding');
    assert.ok(report.summary.critical >= 2);
    assert.ok(report.summary.high >= 2);
  });

  it('enforces --timeout and cleanly kills hung stdio child processes', async () => {
    await assert.rejects(
      () =>
        inspectServer({
          stdio: `"${nodeBin}" "${poisonedServerPath}" --hang`,
          timeoutMs: 350,
        }),
      InspectionTargetError,
    );
  });

  it('supports Streamable HTTP JSON-RPC endpoints returning both JSON and text/event-stream (SSE)', async () => {
    let observedSessionHeader: string | undefined;

    const server = http.createServer((req, res) => {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (chunk: string) => {
        body += chunk;
      });
      req.on('end', () => {
        const rpc = JSON.parse(body) as { id?: number; method: string };

        if (rpc.method === 'initialize') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Mcp-Session-Id': 'session-test-42',
          });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: rpc.id,
              result: {
                protocolVersion: '2024-11-05',
                capabilities: { tools: {} },
                serverInfo: { name: 'http-sse-mcp', version: '2.0.0' },
              },
            }),
          );
          return;
        }

        observedSessionHeader = req.headers['mcp-session-id'] as string | undefined;

        if (rpc.method === 'notifications/initialized') {
          res.writeHead(202);
          res.end();
          return;
        }

        if (rpc.method === 'tools/list') {
          // Respond using SSE framing to verify SSE parser
          res.writeHead(200, { 'Content-Type': 'text/event-stream' });
          const payload = JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id,
            result: {
              tools: [
                {
                  name: 'ping_status',
                  description: 'Check service health status and return current uptime in seconds.',
                  inputSchema: {
                    type: 'object',
                    properties: {},
                    additionalProperties: false,
                  },
                },
              ],
            },
          });
          res.end(`event: message\ndata: ${payload}\n\n`);
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id,
            error: { code: -32601, message: 'Method not found' },
          }),
        );
      });
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    try {
      const addr = server.address() as AddressInfo;
      const endpointUrl = `http://127.0.0.1:${addr.port}/mcp`;

      const report = await inspectServer({ url: endpointUrl, timeoutMs: 5000 });
      assert.equal(observedSessionHeader, 'session-test-42');
      assert.equal(report.findings.length, 0);
      assert.equal(report.inspection?.serverInfo?.name, 'http-sse-mcp');
      assert.equal(report.inspection?.toolCount, 1);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('blocks cloud metadata IPs, IPv4-mapped metadata/private IPs, protocol downgrades, and SSRF redirects', async () => {
    assert.equal(isCloudMetadataOrLinkLocalIp('169.254.169.254'), true);
    assert.equal(isCloudMetadataOrLinkLocalIp('::ffff:169.254.169.254'), true);
    assert.equal(isCloudMetadataOrLinkLocalIp('fe80::1'), true);
    assert.equal(isPrivateOrLoopbackIp('::ffff:127.0.0.1'), true);
    assert.equal(isPrivateOrLoopbackIp('10.1.2.3'), true);
    assert.equal(isPrivateOrLoopbackIp('172.16.5.4'), true);
    assert.equal(isPrivateOrLoopbackIp('192.168.1.10'), true);
    assert.equal(isPrivateOrLoopbackIp('8.8.8.8'), false);

    // Block direct cloud metadata endpoints
    await assert.rejects(
      () => assertSafeHttpInspectionUrl(new URL('http://169.254.169.254/latest/meta-data/')),
      InspectionTargetError,
    );
    await assert.rejects(
      () => assertSafeHttpInspectionUrl(new URL('http://metadata.google.internal/computeMetadata/v1/')),
      InspectionTargetError,
    );

    // Block HTTPS -> HTTP downgrade redirect and remote -> loopback/private SSRF redirect
    await assert.rejects(
      () =>
        assertSafeHttpInspectionUrl(
          new URL('http://example.com/mcp'),
          new URL('https://example.com/mcp'),
        ),
      InspectionTargetError,
    );
    await assert.rejects(
      () =>
        assertSafeHttpInspectionUrl(
          new URL('http://127.0.0.1:8080/admin'),
          new URL('https://untrusted-mcp.example.com/mcp'),
        ),
      InspectionTargetError,
    );
    await assert.rejects(
      () =>
        assertSafeHttpInspectionUrl(
          new URL('https://[::ffff:127.0.0.1]/admin'),
          new URL('https://untrusted-mcp.example.com/mcp'),
        ),
      InspectionTargetError,
    );

    // Live HTTP redirect-to-metadata SSRF blocked via manual redirect inspection
    const redirectServer = http.createServer((_req, res) => {
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });

    await new Promise<void>((resolve) => redirectServer.listen(0, '127.0.0.1', () => resolve()));
    try {
      const addr = redirectServer.address() as AddressInfo;
      await assert.rejects(
        () => inspectServer({ url: `http://127.0.0.1:${addr.port}/mcp`, timeoutMs: 3000 }),
        InspectionTargetError,
      );
    } finally {
      await new Promise<void>((resolve) => redirectServer.close(() => resolve()));
    }
  });

  it('downgrades allowlisted dotenv template/schema filenames to info while keeping live .env refs critical', () => {
    for (const allowedName of SAFE_DOTENV_FILENAMES) {
      const { findings } = analyzeServerCapabilities({
        tools: [
          {
            name: 'inspect_template',
            description: `Reads ${allowedName} in workspace to check key documentation.`,
            inputSchema: {
              type: 'object',
              properties: {
                path: { type: 'string', description: `Relative path to ${allowedName}.` },
              },
            },
          },
        ],
      });
      const mcp104 = findings.filter((f) => f.ruleId === 'MCP104');
      assert.equal(mcp104.length, 2, `Expected 2 info MCP104 findings for ${allowedName}`);
      for (const f of mcp104) {
        assert.equal(f.severity, 'info', `Expected ${allowedName} to be info severity`);
      }
    }

    const sensitiveCases = [
      'Reads .env in project root.',
      'Reads .env.local credentials file.',
      'Reads .env.production config.',
      'Reads .env.example.local override.',
      'Checks .env.example and .env together.',
      'read .env now',
      '~/.env',
      '--env-file=.env',
      'path:.env',
      '[.env]',
      '<.env>',
      '{.env}',
    ];
    for (const desc of sensitiveCases) {
      const { findings } = analyzeServerCapabilities({
        tools: [
          {
            name: 'read_env_tool',
            description: desc,
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });
      const mcp104 = findings.filter((f) => f.ruleId === 'MCP104');
      assert.equal(mcp104.length, 1, `Expected 1 critical MCP104 finding for: ${desc}`);
      assert.equal(mcp104[0]?.severity, 'critical', `Expected critical severity for: ${desc}`);
    }

    // Ensure JS property access like `process.env.KEY` stays clean
    const cleanPropAccess = analyzeServerCapabilities({
      tools: [
        {
          name: 'clean_env_prop',
          description: 'Validates process.env.KEY configuration syntax safely.',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });
    assert.equal(
      cleanPropAccess.findings.filter((f) => f.ruleId === 'MCP104').length,
      0,
    );
  });

  it('matches env-guard-cli tool metadata cleanly after MCP104 dotenv allowlist refinement', () => {
    const envGuardToolsFixture = [
      {
        name: 'list_env_keys',
        description:
          'List environment variable keys discovered across source code, .env.example, .env.schema.json, and .env presence flags within the workspace without exposing any values.',
        inputSchema: {
          type: 'object',
          properties: {
            subpath: {
              type: 'string',
              maxLength: 512,
              description: 'Optional relative directory path inside the workspace root.',
            },
          },
          additionalProperties: false,
        },
      },
      {
        name: 'check_env_drift',
        description:
          'Check workspace environment configuration for missing required variables, unused variables, undocumented keys, and redacted secret hygiene findings without exposing secret values.',
        inputSchema: {
          type: 'object',
          properties: {
            subpath: {
              type: 'string',
              maxLength: 512,
              description: 'Optional relative directory path inside the workspace root.',
            },
          },
          additionalProperties: false,
        },
      },
      {
        name: 'validate_env_schema',
        description:
          'Validate workspace environment variables against a .env.schema.json specification and report rule compliance status without returning secret values.',
        inputSchema: {
          type: 'object',
          properties: {
            schemaPath: {
              type: 'string',
              maxLength: 512,
              description: 'Optional relative path to .env.schema.json inside the workspace root.',
            },
          },
          additionalProperties: false,
        },
      },
    ];

    const { findings } = analyzeServerCapabilities({
      serverName: 'env-guard',
      tools: envGuardToolsFixture,
    });
    const summary = summarizeFindings(findings);

    assert.equal(summary.critical, 1);
    assert.equal(summary.high, 0);
    assert.equal(summary.medium, 0);
    assert.equal(summary.low, 0);
    assert.equal(summary.info, 2);
    assert.equal(summary.total, 3);

    const listKeysFindings = findings.filter((f) => f.location.toolName === 'list_env_keys');
    assert.equal(listKeysFindings.length, 1);
    assert.equal(listKeysFindings[0]?.ruleId, 'MCP104');
    assert.equal(listKeysFindings[0]?.severity, 'critical');

    const driftFindings = findings.filter((f) => f.location.toolName === 'check_env_drift');
    assert.equal(driftFindings.length, 0);

    const validateFindings = findings.filter((f) => f.location.toolName === 'validate_env_schema');
    assert.equal(validateFindings.length, 2);
    assert.ok(validateFindings.every((f) => f.ruleId === 'MCP104' && f.severity === 'info'));
  });
});
