/**
 * Secret redaction and Shannon entropy helpers.
 */

/**
 * Partially masks a sensitive token so audit outputs never leak full credentials.
 */
export function redactSecret(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return '***REDACTED***';
  }
  const prefixLen = Math.min(6, Math.floor(trimmed.length / 4));
  const suffixLen = Math.min(3, Math.floor(trimmed.length / 6));
  const prefix = trimmed.slice(0, prefixLen);
  const suffix = suffixLen > 0 ? trimmed.slice(-suffixLen) : '';
  return `${prefix}***REDACTED***${suffix}`;
}

/**
 * Truncates and sanitizes non-secret evidence snippets for readable output.
 */
export function truncateEvidence(value: string, maxLength = 140): string {
  const normalized = value.replace(/\r?\n/g, '\\n').trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }
  return `${normalized.slice(0, maxLength - 3)}...`;
}

/**
 * Computes the Shannon entropy (in bits per character) of `input`.
 */
export function calculateShannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of input) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = input.length;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
