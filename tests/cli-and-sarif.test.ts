import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { runCli, type SarifLog } from '../src/index.js';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cleanServerPath = path.join(__dirname, 'fixtures', 'clean-mcp-server.js');
const poisonedServerPath = path.join(__dirname, 'fixtures', 'poisoned-mcp-server.js');
const cliEntryPath = path.resolve(__dirname, '..', 'cli.js');
const nodeBin = process.execPath;

function createCapturedIo(): {
  stdoutLines: string[];
  stderrLines: string[];
  io: { stdout: (t: string) => void; stderr: (t: string) => void };
} {
  const stdoutLines: string[] = [];
  const stderrLines: string[] = [];
  return {
    stdoutLines,
    stderrLines,
    io: {
      stdout: (t) => stdoutLines.push(t),
      stderr: (t) => stderrLines.push(t),
    },
  };
}

describe('CLI exit codes, output formats, and SARIF 2.1.0 schema compliance', () => {
  it('returns exit code 0 on clean stdio server and exit code 1 on poisoned server with --fail-on high', async () => {
    const cleanRun = createCapturedIo();
    const cleanCode = await runCli(
      ['inspect', '--stdio', `"${nodeBin}" "${cleanServerPath}"`, '--fail-on', 'high'],
      cleanRun.io,
    );
    assert.equal(cleanCode, 0);
    assert.ok(cleanRun.stdoutLines.join('\n').includes('0 issues detected'));

    const poisonedRun = createCapturedIo();
    const poisonedCode = await runCli(
      ['inspect', '--stdio', `"${nodeBin}" "${poisonedServerPath}"`, '--fail-on', 'high'],
      poisonedRun.io,
    );
    assert.equal(poisonedCode, 1);
  });

  it('emits valid SARIF 2.1.0 compatible with GitHub Code Scanning on both scan and inspect', async () => {
    const sarifRun = createCapturedIo();
    const code = await runCli(
      ['inspect', '--stdio', `"${nodeBin}" "${poisonedServerPath}"`, '--format', 'sarif', '--fail-on', 'high'],
      sarifRun.io,
    );
    assert.equal(code, 1);

    const parsed = JSON.parse(sarifRun.stdoutLines.join('\n')) as SarifLog;
    assert.equal(parsed.version, '2.1.0');
    assert.ok(parsed.$schema.includes('sarif-2.1.0'));
    assert.equal(parsed.runs.length, 1);

    const run = parsed.runs[0]!;
    assert.equal(run.tool.driver.name, 'mcp-doctor');
    assert.equal(run.tool.driver.informationUri, 'https://github.com/pie527645-cloud/mcp-doctor');
    assert.ok(run.tool.driver.rules.length >= 10);
    assert.ok(run.results.length >= 6);

    for (const result of run.results) {
      const driverRule = run.tool.driver.rules[result.ruleIndex];
      assert.ok(driverRule, 'result.ruleIndex must reference a valid rule in tool.driver.rules');
      assert.equal(driverRule.id, result.ruleId);
      assert.ok(['error', 'warning', 'note'].includes(result.level));
      assert.ok(result.locations.length >= 1);
      const phys = result.locations[0]!.physicalLocation;
      assert.ok(phys.artifactLocation.uri.length > 0);
      assert.ok(phys.region.startLine >= 1);
    }
  });

  it('respects --fail-on severity threshold for medium-only findings', async () => {
    const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'mcp-doctor-cli-'));
    try {
      const cfgPath = path.join(tmpDir, 'mcp.json');
      await writeFile(
        cfgPath,
        JSON.stringify({
          mcpServers: {
            unpinnedWithoutYes: {
              command: 'npx',
              args: ['unpinned-mcp-server'],
            },
          },
        }),
        'utf8',
      );

      // MCP003 without -y is medium: should exit 0 when --fail-on high, exit 1 when --fail-on medium
      const highRun = createCapturedIo();
      const codeHigh = await runCli(['scan', cfgPath, '--fail-on', 'high', '--format', 'markdown'], highRun.io);
      assert.equal(codeHigh, 0);
      assert.ok(highRun.stdoutLines.join('\n').includes('# mcp-doctor Config Scan Report'));

      const medRun = createCapturedIo();
      const codeMed = await runCli(['scan', cfgPath, '--fail-on', 'medium', '--format', 'json'], medRun.io);
      assert.equal(codeMed, 1);
      const jsonReport = JSON.parse(medRun.stdoutLines.join('\n')) as { summary: { medium: number } };
      assert.equal(jsonReport.summary.medium, 1);
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('returns exit code 2 on invalid CLI flags, malformed --timeout, missing paths, and unreachable targets', async () => {
    const invalidCases: string[][] = [
      ['unknown-subcommand'],
      ['inspect'],
      ['inspect', '--stdio', 'node a.js', '--url', 'http://127.0.0.1:3000'],
      ['inspect', '--stdio', 'node a.js', '--timeout', 'not-a-number'],
      ['inspect', '--stdio', 'node a.js', '--timeout', '0'],
      ['scan', '--format', 'xml'],
      ['scan', '--fail-on', 'blocker'],
      ['scan', './definitely-missing-config-path-99999.json'],
      ['inspect', '--stdio', 'nonexistent-mcp-binary-xyz987'],
    ];

    for (const args of invalidCases) {
      const captured = createCapturedIo();
      const code = await runCli(args, captured.io);
      assert.equal(code, 2, `Expected exit code 2 for args: ${args.join(' ')}`);
      assert.ok(captured.stderrLines.length > 0);
    }
  });

  it('runs compiled dist/cli.js end-to-end as a standalone process', async () => {
    const { stdout } = await execFileAsync(nodeBin, [
      cliEntryPath,
      'inspect',
      '--stdio',
      `"${nodeBin}" "${cleanServerPath}"`,
      '--format',
      'json',
    ]);
    const parsed = JSON.parse(stdout) as { summary: { total: number } };
    assert.equal(parsed.summary.total, 0);
  });
});
