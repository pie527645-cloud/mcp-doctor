import { calculateShannonEntropy, redactSecret } from '../utils/redact.js';

/**
 * Result of matching a secret or high-entropy credential in configuration text.
 */
export interface SecretMatch {
  provider: string;
  redactedValue: string;
}

interface SecretRule {
  provider: string;
  pattern: RegExp;
  extractToken?: (match: RegExpExecArray) => string;
}

const KNOWN_SECRET_PATTERNS: readonly SecretRule[] = [
  {
    provider: 'AWS Access Key ID',
    pattern: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
  },
  {
    provider: 'Anthropic API Key',
    pattern: /\b(sk-ant-(?:api\d{2}-|admin\d{2}-)?[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    provider: 'OpenAI API Key',
    pattern: /\b(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    provider: 'GitHub Token',
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
  },
  {
    provider: 'Apify API Token',
    pattern: /\b(apify_api_[A-Za-z0-9]{20,})\b/g,
  },
  {
    provider: 'Stripe API Key',
    pattern: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
  },
  {
    provider: 'Slack Token',
    pattern: /\b(xox[baprs]-[0-9A-Za-z-]{16,})\b/g,
  },
  {
    provider: 'Slack Webhook URL',
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g,
  },
  {
    provider: 'Bearer Token',
    pattern: /\bBearer\s+([A-Za-z0-9._~+/=-]{20,})\b/gi,
    extractToken: (match) => match[1] ?? match[0],
  },
  {
    provider: 'PEM Private Key',
    pattern: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/g,
  },
  {
    provider: 'Credentialed Connection URI',
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/]+:([^@\s/]{4,})@/gi,
    extractToken: (match) => match[1] ?? match[0],
  },
];

const SENSITIVE_KEY_NAME_REGEX =
  /(?:secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?key|authorization)/i;

const CLI_SECRET_FLAG_REGEX =
  /^(?:--?(?:api[-_]?key|token|access[-_]?token|secret|password|auth[-_]?token))(?:=(.+))?$/i;

/**
 * Returns true if `value` looks like an environment variable interpolation or obvious template placeholder.
 */
export function isPlaceholderOrInterpolation(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;

  if (/^\$\{[^{}]+\}$/.test(trimmed)) return true;
  if (/^\$[A-Z_][A-Z0-9_]*$/.test(trimmed)) return true;
  if (/^%[A-Za-z_][A-Za-z0-9_]*%$/.test(trimmed)) return true;
  if (/^<[^<>]+>$/.test(trimmed)) return true;
  if (/^\{\{[^{}]+\}\}$/.test(trimmed)) return true;

  if (
    /^(?:your[-_]|replace[-_]?me|changeme|insert[-_]|todo|example|dummy|placeholder|none|null|undefined|false|true|xxx+)$/i.test(
      trimmed,
    )
  ) {
    return true;
  }
  if (/(?:YOUR_[A-Z0-9_]+|INSERT_[A-Z0-9_]+|_HERE$)/i.test(trimmed)) {
    return true;
  }

  return false;
}

function looksLikePathOrPlainUrl(value: string): boolean {
  if (/^(?:[A-Za-z]:\\|\/|\.\.?\/|~\/)/.test(value)) return true;
  if (/^https?:\/\//i.test(value) && !/:\/\/[^:\s/]+:[^@\s/]+@/.test(value)) return true;
  return false;
}

function hasMixedCharacterClasses(value: string): boolean {
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/[0-9]/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  return classes >= 2;
}

/**
 * Scans an arbitrary string for known provider secret prefixes, bearer tokens, or credentialed URIs.
 */
export function scanStringForSecrets(value: string): SecretMatch[] {
  if (!value || isPlaceholderOrInterpolation(value)) {
    return [];
  }

  const matches: SecretMatch[] = [];
  for (const rule of KNOWN_SECRET_PATTERNS) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let execResult = regex.exec(value);
    while (execResult !== null) {
      const rawToken = rule.extractToken ? rule.extractToken(execResult) : (execResult[1] ?? execResult[0]);
      if (!isPlaceholderOrInterpolation(rawToken)) {
        matches.push({
          provider: rule.provider,
          redactedValue: redactSecret(rawToken),
        });
      }
      execResult = regex.exec(value);
    }
  }

  return matches;
}

/**
 * Scans a key-value pair (such as `env` or `headers` entries) for both known secret formats
 * and high-entropy credentials assigned to secret-named keys.
 */
export function scanKeyValueForSecrets(key: string, value: string): SecretMatch[] {
  const directMatches = scanStringForSecrets(value);
  if (directMatches.length > 0) {
    return directMatches;
  }

  const trimmed = value.trim();
  if (
    !SENSITIVE_KEY_NAME_REGEX.test(key) ||
    trimmed.length < 20 ||
    /\s/.test(trimmed) ||
    isPlaceholderOrInterpolation(trimmed) ||
    looksLikePathOrPlainUrl(trimmed)
  ) {
    return [];
  }

  const entropy = calculateShannonEntropy(trimmed);
  if (entropy >= 3.75 && hasMixedCharacterClasses(trimmed)) {
    return [
      {
        provider: `High-Entropy Secret (${key})`,
        redactedValue: redactSecret(trimmed),
      },
    ];
  }

  return [];
}

/**
 * Scans an `args` array for inline secret flags (e.g. `--api-key value` or `--token=value`)
 * as well as known provider token formats without duplicate reporting.
 */
export function scanArgsForSecrets(args: readonly string[]): Array<SecretMatch & { argIndex: number }> {
  const results: Array<SecretMatch & { argIndex: number }> = [];
  const seen = new Set<string>();

  function pushUnique(argIndex: number, match: SecretMatch): void {
    const key = `${argIndex}:${match.provider}:${match.redactedValue}`;
    if (!seen.has(key)) {
      seen.add(key);
      results.push({ ...match, argIndex });
    }
  }

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    const flagMatch = CLI_SECRET_FLAG_REGEX.exec(arg);

    if (flagMatch) {
      const inlineValue = flagMatch[1];
      if (inlineValue !== undefined) {
        for (const m of scanKeyValueForSecrets('api_key', inlineValue)) {
          pushUnique(i, m);
        }
        continue;
      }
      if (i + 1 < args.length && !args[i + 1]!.startsWith('-')) {
        for (const m of scanKeyValueForSecrets('api_key', args[i + 1]!)) {
          pushUnique(i + 1, m);
        }
        i += 1;
        continue;
      }
    }

    for (const m of scanStringForSecrets(arg)) {
      pushUnique(i, m);
    }
  }

  return results;
}
