import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CliUsageError, tokenizeCommand } from '../src/index.js';

describe('tokenizeCommand (quote-aware argv tokenizer)', () => {
  it('parses simple whitespace-separated commands', () => {
    const res = tokenizeCommand('node dist/server.js --port 3000');
    assert.deepEqual(res, {
      command: 'node',
      args: ['dist/server.js', '--port', '3000'],
    });
  });

  it('preserves spaces inside double and single quotes', () => {
    const res = tokenizeCommand(`node "path with spaces/server.js" --label 'My MCP Server'`);
    assert.deepEqual(res, {
      command: 'node',
      args: ['path with spaces/server.js', '--label', 'My MCP Server'],
    });
  });

  it('preserves Windows path backslashes inside double quotes and unquoted paths', () => {
    const quoted = tokenizeCommand(`"C:\\Program Files\\nodejs\\node.exe" "C:\\Users\\Dev\\my server\\index.js"`);
    assert.deepEqual(quoted, {
      command: 'C:\\Program Files\\nodejs\\node.exe',
      args: ['C:\\Users\\Dev\\my server\\index.js'],
    });

    const unquoted = tokenizeCommand('C:\\Tools\\node.exe dist\\mcp\\server.js');
    assert.deepEqual(unquoted, {
      command: 'C:\\Tools\\node.exe',
      args: ['dist\\mcp\\server.js'],
    });
  });

  it('handles escaped double quotes inside double-quoted arguments', () => {
    const res = tokenizeCommand('node server.js --json "{\\"enabled\\":true}"');
    assert.deepEqual(res, {
      command: 'node',
      args: ['server.js', '--json', '{"enabled":true}'],
    });
  });

  it('keeps shell metacharacters as inert literal argument tokens without expansion', () => {
    const res = tokenizeCommand('node server.js --arg "safe && echo pwned; $(whoami) `id`"');
    assert.deepEqual(res, {
      command: 'node',
      args: ['server.js', '--arg', 'safe && echo pwned; $(whoami) `id`'],
    });
  });

  it('throws CliUsageError on empty input or unclosed quotes', () => {
    assert.throws(() => tokenizeCommand('   '), CliUsageError);
    assert.throws(() => tokenizeCommand('node "unclosed/path.js'), CliUsageError);
    assert.throws(() => tokenizeCommand("node 'unclosed/single.js"), CliUsageError);
  });
});
