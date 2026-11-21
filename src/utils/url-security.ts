import dns from 'node:dns/promises';
import net from 'node:net';
import { InspectionTargetError } from '../types.js';

const METADATA_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

/**
 * Parses an IPv4 address into a 32-bit unsigned integer, or returns null if invalid.
 */
function ipv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number.parseInt(part, 10);
    if (octet < 0 || octet > 255) return null;
    result = ((result << 8) | octet) >>> 0;
  }
  return result;
}

function inCidrV4(ipInt: number, baseIp: string, prefixBits: number): boolean {
  const baseInt = ipv4ToUint32(baseIp);
  if (baseInt === null) return false;
  const mask = prefixBits === 0 ? 0 : (~0 << (32 - prefixBits)) >>> 0;
  return (ipInt & mask) >>> 0 === (baseInt & mask) >>> 0;
}

/**
 * Extracts embedded IPv4 string if `ip` is an IPv4-mapped IPv6 address (e.g. `::ffff:127.0.0.1` or `::ffff:7f00:1`).
 */
function extractMappedIpv4(ipv6: string): string | null {
  const lower = ipv6.toLowerCase();
  if (!lower.startsWith('::ffff:')) return null;
  const tail = lower.slice('::ffff:'.length);
  if (net.isIPv4(tail)) return tail;

  const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
  if (hexMatch) {
    const hi = Number.parseInt(hexMatch[1]!, 16);
    const lo = Number.parseInt(hexMatch[2]!, 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return null;
}

/**
 * Returns true if the IP address is cloud instance metadata / link-local (`169.254.0.0/16`, `100.100.100.200`, `fe80::/10`).
 */
export function isCloudMetadataOrLinkLocalIp(ip: string): boolean {
  const mappedV4 = net.isIPv6(ip) ? extractMappedIpv4(ip) : null;
  const v4Candidate = mappedV4 ?? (net.isIPv4(ip) ? ip : null);

  if (v4Candidate) {
    const ipInt = ipv4ToUint32(v4Candidate);
    if (ipInt === null) return false;
    // AWS/GCP/Azure link-local metadata 169.254.0.0/16 and Alibaba metadata 100.100.100.200/32
    return inCidrV4(ipInt, '169.254.0.0', 16) || v4Candidate === '100.100.100.200';
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    // fe80::/10 link-local or AWS IPv6 IMDS fd00:ec2::254
    return /^fe[89ab][0-9a-f]:/.test(lower) || lower === 'fd00:ec2::254';
  }

  return false;
}

/**
 * Returns true if the IP address is loopback, unspecified, private RFC1918, CGNAT, unique-local, or link-local.
 */
export function isPrivateOrLoopbackIp(ip: string): boolean {
  if (isCloudMetadataOrLinkLocalIp(ip)) return true;

  const mappedV4 = net.isIPv6(ip) ? extractMappedIpv4(ip) : null;
  const v4Candidate = mappedV4 ?? (net.isIPv4(ip) ? ip : null);

  if (v4Candidate) {
    const ipInt = ipv4ToUint32(v4Candidate);
    if (ipInt === null) return true;
    return (
      inCidrV4(ipInt, '0.0.0.0', 8) ||
      inCidrV4(ipInt, '10.0.0.0', 8) ||
      inCidrV4(ipInt, '100.64.0.0', 10) ||
      inCidrV4(ipInt, '127.0.0.0', 8) ||
      inCidrV4(ipInt, '172.16.0.0', 12) ||
      inCidrV4(ipInt, '192.168.0.0', 16)
    );
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    // fc00::/7 unique local IPv6
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  }

  return false;
}

/**
 * Returns true if `hostname` is an explicit localhost/loopback literal.
 */
export function isLoopbackHost(hostname: string): boolean {
  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (clean === 'localhost' || clean === '::1') return true;
  const mapped = net.isIPv6(clean) ? extractMappedIpv4(clean) : null;
  const v4 = mapped ?? (net.isIPv4(clean) ? clean : null);
  if (v4) {
    const ipInt = ipv4ToUint32(v4);
    return ipInt !== null && inCidrV4(ipInt, '127.0.0.0', 8);
  }
  return false;
}

/**
 * Validates that an HTTP MCP inspection target never connects to cloud metadata services,
 * and when redirected from a non-private origin, never hops to private/loopback/cleartext targets.
 */
export async function assertSafeHttpInspectionUrl(targetUrl: URL, redirectedFrom?: URL): Promise<void> {
  if (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') {
    throw new InspectionTargetError(`Unsupported redirect/target protocol "${targetUrl.protocol}".`);
  }

  if (redirectedFrom && redirectedFrom.protocol === 'https:' && targetUrl.protocol === 'http:') {
    throw new InspectionTargetError(
      `Blocked insecure HTTPS-to-HTTP redirect from "${redirectedFrom.origin}" to "${targetUrl.origin}".`,
    );
  }

  const host = targetUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (METADATA_HOSTNAMES.has(host)) {
    throw new InspectionTargetError(`Blocked cloud metadata hostname "${host}" in HTTP inspection.`);
  }

  const literalIpType = net.isIP(host);
  if (literalIpType !== 0) {
    if (isCloudMetadataOrLinkLocalIp(host)) {
      throw new InspectionTargetError(`Blocked cloud metadata / link-local IP "${host}" in HTTP inspection.`);
    }
    if (redirectedFrom && !isLoopbackHost(redirectedFrom.hostname) && isPrivateOrLoopbackIp(host)) {
      throw new InspectionTargetError(
        `Blocked SSRF redirect from "${redirectedFrom.origin}" to internal/private address "${host}".`,
      );
    }
    return;
  }

  if (isLoopbackHost(host)) {
    if (redirectedFrom && !isLoopbackHost(redirectedFrom.hostname)) {
      throw new InspectionTargetError(
        `Blocked SSRF redirect from "${redirectedFrom.origin}" to loopback host "${host}".`,
      );
    }
    return;
  }

  // Resolve DNS to catch DNS-rebinding or hostname aliases pointing to metadata IPs (or private IPs on redirects)
  let records: Array<{ address: string; family: number }>;
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch (err) {
    throw new InspectionTargetError(
      `Failed resolving hostname "${host}": ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }

  for (const rec of records) {
    if (isCloudMetadataOrLinkLocalIp(rec.address)) {
      throw new InspectionTargetError(
        `Blocked hostname "${host}" resolving to cloud metadata / link-local IP "${rec.address}".`,
      );
    }
    if (redirectedFrom && !isLoopbackHost(redirectedFrom.hostname) && isPrivateOrLoopbackIp(rec.address)) {
      throw new InspectionTargetError(
        `Blocked SSRF redirect from "${redirectedFrom.origin}" to "${host}" (${rec.address}).`,
      );
    }
  }
}
