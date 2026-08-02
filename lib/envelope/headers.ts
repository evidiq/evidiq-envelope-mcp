// Received-chain forensics: hop consistency, timestamp ordering, injected or
// duplicated critical headers, gaps that indicate a forged path. Structural only.

export interface ReceivedHop {
  index: number;
  fromHost?: string;
  byHost?: string;
  withProto?: string;
  forAddr?: string;
  timestamp?: string;
  date?: Date | null;
}

export interface HeaderChainFinding {
  kind: string;
  severity: "info" | "warning" | "high";
  message: string;
}

const RECEIVED_RE =
  /^Received:\s*(.*)$/;
const FROM_BY_RE =
  /from\s+(\S+)(?:\s+\(([^)]*)\))?/i;
const BY_RE =
  /\bby\s+(\S+)/i;
const WITH_RE =
  /\bwith\s+(\S+)/i;
const FOR_RE =
  /\bfor\s+<([^>]+)>/i;
const DATE_RE =
  /;\s*([A-Za-z]{3},?\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})/;

const CRITICAL_HEADERS = [
  "from",
  "to",
  "subject",
  "date",
  "message-id",
  "reply-to",
  "sender",
  "return-path",
];

export function parseReceivedChain(raw: string): ReceivedHop[] {
  const lines = raw.split(/\r?\n/);
  const hops: ReceivedHop[] = [];
  let current: { text: string; key: string } | null = null;
  const blocks: string[] = [];

  for (const line of lines) {
    if (line.toLowerCase().startsWith("received:")) {
      if (current) blocks.push(current.text);
      current = { key: "received", text: line.slice("received:".length).trim() };
    } else if (/^\s/.test(line) && current) {
      current.text += " " + line.trim();
    } else if (current) {
      blocks.push(current.text);
      current = null;
    }
  }
  if (current) blocks.push(current.text);

  blocks.reverse().forEach((text, i) => {
    const from = text.match(FROM_BY_RE);
    const by = text.match(BY_RE);
    const withProto = text.match(WITH_RE);
    const forAddr = text.match(FOR_RE);
    const dateStr = text.match(DATE_RE)?.[1];
    let date: Date | null = null;
    if (dateStr) {
      const d = new Date(dateStr);
      date = isNaN(d.getTime()) ? null : d;
    }
    hops.push({
      index: i + 1,
      fromHost: from?.[1] ?? undefined,
      byHost: by?.[1] ?? undefined,
      withProto: withProto?.[1] ?? undefined,
      forAddr: forAddr?.[1] ?? undefined,
      timestamp: dateStr,
      date,
    });
  });

  return hops;
}

export function auditHeaderChain(raw: string): {
  hops: ReceivedHop[];
  findings: HeaderChainFinding[];
  headerInventory: Record<string, number>;
} {
  const findings: HeaderChainFinding[] = [];
  const headerBlock = raw.split(/\r?\n\r?\n/, 1)[0];
  const headerInventory: Record<string, number> = {};

  for (const line of headerBlock.split(/\r?\n/)) {
    if (/^\s/.test(line)) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    headerInventory[key] = (headerInventory[key] ?? 0) + 1;
  }

  for (const key of CRITICAL_HEADERS) {
    const count = headerInventory[key] ?? 0;
    if (count > 1) {
      findings.push({
        kind: "duplicate-critical-header",
        severity: "high",
        message: `header "${key}" appears ${count} times — duplicates can hide a forged value`,
      });
    }
  }

  const hops = parseReceivedChain(raw);

  if (hops.length === 0) {
    findings.push({
      kind: "no-received-chain",
      severity: "warning",
      message: "no Received headers — cannot reconstruct the delivery path",
    });
  }

  // Timestamp ordering: hop N should be received before hop N+1. hops are
  // already in delivery order (index 1 = first).
  const dated = hops.filter((h) => h.date);
  for (let i = 1; i < dated.length; i++) {
    const prev = dated[i - 1];
    const cur = dated[i];
    if (prev.date && cur.date && prev.date.getTime() > cur.date.getTime()) {
      findings.push({
        kind: "timestamp-reversal",
        severity: "high",
        message: `Received timestamps out of order: hop ${prev.index} (${prev.timestamp}) is later than hop ${cur.index} (${cur.timestamp})`,
      });
    }
  }

  // Hop consistency: a hop should not claim to be received by a host that an
  // earlier hop claims to be from (a tight loop suggests an injected chain).
  for (let i = 1; i < hops.length; i++) {
    const cur = hops[i];
    const prev = hops[i - 1];
    if (
      cur.byHost &&
      prev.fromHost &&
      cur.byHost.toLowerCase() === prev.fromHost.toLowerCase()
    ) {
      findings.push({
        kind: "hop-loop",
        severity: "warning",
        message: `hop ${cur.index} was received by ${cur.byHost}, the same host hop ${prev.index} claims to be from`,
      });
    }
  }

  if (hops.length >= 1 && !hops[hops.length - 1].byHost) {
    findings.push({
      kind: "incomplete-chain",
      severity: "info",
      message: "the innermost Received header has no receiving host",
    });
  }

  return { hops, findings, headerInventory };
}
