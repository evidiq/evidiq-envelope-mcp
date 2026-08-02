import { promises as dnsPromises } from "node:dns";

export interface PinnedDnsEntry {
  domain: string;
  rrtype: string;
  records: string[];
}

// Node's dns.promises.resolveTxt returns string[][] (TXT records split into
// segments). mailauth joins the segments; we keep them joined for pinning.
function flattenTxt(rows: string[][]): string[] {
  return rows.map((row) => row.join(""));
}

/**
 * Real DNS with a pinning recorder. Every answer used by a check is recorded so
 * the report can pin the DNS snapshot the verdict was derived from (PLAN §3).
 * The resolver signature matches mailauth's DNSResolver.
 */
export class PinningDns {
  private resolver: dnsPromises.Resolver;
  private pinned: Map<string, PinnedDnsEntry>;

  constructor(resolverAddresses?: string[]) {
    this.resolver = new dnsPromises.Resolver();
    this.pinned = new Map();
    if (resolverAddresses && resolverAddresses.length > 0) {
      try {
        this.resolver.setServers(resolverAddresses);
      } catch {
        // invalid resolver list — fall back to the system defaults
      }
    }
  }

  getPinned(): PinnedDnsEntry[] {
    return [...this.pinned.values()].sort((a, b) =>
      (a.domain + a.rrtype).localeCompare(b.domain + b.rrtype)
    );
  }

  private record(domain: string, rrtype: string, records: string[]) {
    const key = `${domain}\u0000${rrtype}`.toLowerCase();
    if (!this.pinned.has(key)) {
      this.pinned.set(key, { domain: domain.toLowerCase(), rrtype, records });
    }
  }

  async query(domain: string, rrtype: string): Promise<string[]> {
    try {
      if (rrtype === "TXT") {
        const rows = await this.resolver.resolveTxt(domain);
        const flat = flattenTxt(rows);
        this.record(domain, "TXT", flat);
        return flat;
      }
      if (rrtype === "MX") {
        const rows = await this.resolver.resolveMx(domain);
        const flat = rows.map((r) => `${r.priority} ${r.exchange}`);
        this.record(domain, "MX", flat);
        return flat;
      }
      if (rrtype === "A") {
        const rows = await this.resolver.resolve4(domain);
        this.record(domain, "A", rows);
        return rows;
      }
      if (rrtype === "AAAA") {
        const rows = await this.resolver.resolve6(domain);
        this.record(domain, "AAAA", rows);
        return rows;
      }
      const rows = await this.resolver.resolve(domain, rrtype as any);
      const flat = Array.isArray(rows) ? rows.map((r) => String(r)) : [String(rows)];
      this.record(domain, rrtype, flat);
      return flat;
    } catch (err: any) {
      const code = err?.code ?? "EUNKNOWN";
      const e = new Error(`query${rrtype} ${domain}: ${code}`) as Error & { code: string };
      e.code = code;
      throw e;
    }
  }

  /** mailauth-compatible resolver (throws ENOTFOUND on missing records). */
  get mailauthResolver() {
    return async (domain: string, rrtype: string): Promise<string[][]> => {
      const records = await this.query(domain, rrtype);
      return records.map((r) => [r]);
    };
  }
}
