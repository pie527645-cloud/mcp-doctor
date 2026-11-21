import { CliUsageError } from '../types.js';

/**
 * Parsed command and argument list suitable for `spawn(command, args, { shell: false })`.
 */
export interface TokenizedCommand {
  command: string;
  args: string[];
}

/**
 * Safely tokenizes a CLI command string into `{ command, args }` without invoking a shell.
 *
 * Rules:
 * - Splits on unquoted whitespace (` `, `\t`).
 * - Single-quoted strings (`'...'`) preserve all characters literally.
 * - Double-quoted strings (`"..."`) preserve whitespace and allow `\"` and `\\"` escaping
 *   while preserving Windows path backslashes (such as `"C:\Program Files\nodejs\node.exe"`).
 * - Outside quotes, `\ `, `\"`, and `\'` escape the next character, while path backslashes
 *   before normal filename characters are preserved cross-platform.
 * - Throws `CliUsageError` on empty input or unclosed quotes.
 */
export function tokenizeCommand(commandLine: string): TokenizedCommand {
  const trimmed = commandLine.trim();
  if (trimmed.length === 0) {
    throw new CliUsageError('Command string passed to --stdio cannot be empty.');
  }

  const tokens: string[] = [];
  let current = '';
  let inToken = false;
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i]!;

    if (quote === "'") {
      if (ch === "'") {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }

    if (quote === '"') {
      if (ch === '\\') {
        const next = trimmed[i + 1];
        if (next === '"') {
          current += '"';
          i += 1;
          continue;
        }
        if (next === '\\' && trimmed[i + 2] === '"') {
          current += '\\';
          i += 1;
          continue;
        }
        current += ch;
        continue;
      }
      if (ch === '"') {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }

    // Outside quotes
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      if (inToken) {
        tokens.push(current);
        current = '';
        inToken = false;
      }
      continue;
    }

    if (ch === "'" || ch === '"') {
      quote = ch;
      inToken = true;
      continue;
    }

    if (ch === '\\') {
      const next = trimmed[i + 1];
      if (next === ' ' || next === '"' || next === "'") {
        current += next;
        inToken = true;
        i += 1;
        continue;
      }
    }

    current += ch;
    inToken = true;
  }

  if (quote !== null) {
    throw new CliUsageError(`Unclosed ${quote === '"' ? 'double' : 'single'} quote in --stdio command.`);
  }

  if (inToken) {
    tokens.push(current);
  }

  const command = tokens[0];
  if (!command) {
    throw new CliUsageError('Command string passed to --stdio resolved to no executable.');
  }

  return {
    command,
    args: tokens.slice(1),
  };
}
