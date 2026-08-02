import { createHash } from "node:crypto";
import { simpleParser } from "mailparser";

export interface HeaderEntry {
  key: string;
  value: string;
}

export interface ParsedMessage {
  ok: boolean;
  error?: string;
  messageHash: string;
  rawLength: number;
  headerCount: number;
  headerInventory: Record<string, number>;
  from?: string;
  fromDomain?: string;
  fromDisplayName?: string;
  replyTo?: string;
  returnPath?: string;
  subject?: string;
  messageId?: string;
  receivedCount: number;
  attachmentNames: { name: string; contentType: string; size: number }[];
  linkCount: number;
  bodySnippet: string;
  bodyLength: number;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf-8").digest("hex");
}

function domainOf(email: string | undefined): string | undefined {
  if (!email) return undefined;
  const m = email.trim().match(/@([^\s>]+)/);
  return m ? m[1].toLowerCase().replace(/\.$/, "") : undefined;
}

function displayNameOf(headerValue: string | undefined): string | undefined {
  if (!headerValue) return undefined;
  const m = headerValue.match(/^"([^"]+)"/) ?? headerValue.match(/^([^<@]+)</);
  if (m && m[1].trim()) return m[1].trim();
  return undefined;
}

/**
 * Parse a raw RFC 5322 message into an inventory. Structure only — no verdicts,
 * no persistence of the raw message. The message hash is what any report refers to.
 */
export async function parseMessage(raw: string): Promise<ParsedMessage> {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    return { ok: false, error: "empty message", messageHash: sha256Hex(raw ?? ""), rawLength: 0, headerCount: 0, headerInventory: {}, receivedCount: 0, attachmentNames: [], linkCount: 0, bodySnippet: "", bodyLength: 0 };
  }

  const headerBlock = raw.split(/\r?\n\r?\n/, 1)[0];
  const bodyStart = raw.indexOf("\n\n");
  const body = bodyStart === -1 ? "" : raw.slice(bodyStart + 2);

  const headers: HeaderEntry[] = [];
  const headerInventory: Record<string, number> = {};
  const lines = headerBlock.split(/\r?\n/);
  let current: HeaderEntry | null = null;
  for (const line of lines) {
    if (/^\s/.test(line) && current) {
      current.value += " " + line.trim();
      continue;
    }
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    current = { key, value };
    headers.push(current);
    headerInventory[key] = (headerInventory[key] ?? 0) + 1;
  }

  const getFirst = (key: string): string | undefined =>
    headers.find((h) => h.key === key)?.value;

  const from = getFirst("from");
  const replyTo = getFirst("reply-to");
  const returnPath = getFirst("return-path");

  let parsed: Awaited<ReturnType<typeof simpleParser>> | null = null;
  const attachmentNames: { name: string; contentType: string; size: number }[] = [];
  try {
    parsed = await simpleParser(raw);
    for (const a of parsed.attachments ?? []) {
      attachmentNames.push({
        name: a.filename ?? "(unnamed)",
        contentType: a.contentType ?? "",
        size: (a.content?.length ?? 0) as number,
      });
    }
  } catch {
    // mailparser failure must not fail the free structural tool; the header
    // inventory above still stands.
  }

  const linkCount = (body.match(/https?:\/\//g) ?? []).length;

  return {
    ok: true,
    messageHash: sha256Hex(raw),
    rawLength: raw.length,
    headerCount: headers.length,
    headerInventory,
    from,
    fromDomain: domainOf(from),
    fromDisplayName: displayNameOf(from),
    replyTo,
    returnPath: returnPath === "<>" ? undefined : returnPath,
    subject: getFirst("subject"),
    messageId: getFirst("message-id"),
    receivedCount: headerInventory["received"] ?? 0,
    attachmentNames,
    linkCount,
    bodySnippet: body.slice(0, 200),
    bodyLength: body.length,
  };
}
