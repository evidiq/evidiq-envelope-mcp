import { describe, expect, it } from "vitest";
import { assessSpoofing, detectLookalike } from "../lib/envelope/spoofing.js";
import { auditHeaderChain, parseReceivedChain } from "../lib/envelope/headers.js";
import { assessAttachment, assessAttachmentSurface } from "../lib/envelope/attachments.js";
import { assessLink, assessLinkSurface } from "../lib/envelope/links.js";

describe("spoofing engine", () => {
  it("detects homoglyph domains", () => {
    const hit = detectLookalike("gооgle.com", "google.com", 1);
    expect(hit).not.toBeNull();
    expect(hit!.kind).toBe("homoglyph");
    expect(hit!.severity).toBe("high");
  });

  it("detects 1-edit lookalikes", () => {
    const hit = detectLookalike("g0ogle.com", "google.com", 1);
    expect(hit).not.toBeNull();
    expect(hit!.kind).toBe("lookalike");
  });

  it("does not flag unrelated domains", () => {
    expect(detectLookalike("example.org", "example.com", 1)).toBeNull();
    expect(detectLookalike("google.co.uk", "google.com", 1)).toBeNull();
  });

  it("flags punycode domains", () => {
    const findings = assessSpoofing({
      from: "admin@xn--80ak6aa92e.com",
      expectedSenders: ["billing@example.com"],
    });
    expect(findings.some((f) => f.kind === "punycode-domain")).toBe(true);
  });

  it("flags display-name email mismatch", () => {
    const findings = assessSpoofing({
      from: '"Billing Dept <billing@example.com>" <alice@attacker.net>',
      fromDisplayName: "Billing Dept <billing@example.com>",
      expectedSenders: ["billing@example.com"],
    });
    expect(findings.some((f) => f.kind === "display-name-email-mismatch")).toBe(true);
  });

  it("flags Reply-To divergence", () => {
    const findings = assessSpoofing({
      from: "alice@example.com",
      replyTo: "evil@attacker.net",
    });
    expect(findings.some((f) => f.kind === "reply-to-divergence")).toBe(true);
  });

  it("clean message yields no indicators", () => {
    const findings = assessSpoofing({
      from: "alice@example.com",
      fromDisplayName: "Alice",
      replyTo: "alice@example.com",
      expectedSenders: ["alice@example.com"],
    });
    expect(findings.length).toBe(0);
  });
});

describe("header chain forensics", () => {
  const msg = [
    "Received: from mx2.isp.net (mx2.isp.net [198.51.100.9])",
    "\tby mx.example.com with ESMTP id abc1",
    "\tfor <bob@example.com>; Fri, 02 Jan 2026 10:01:00 +0000",
    "Received: from mail.attacker.net (mail.attacker.net [203.0.113.1])",
    "\tby mx2.isp.net with ESMTP id xyz9",
    "\tfor <bob@example.com>; Fri, 02 Jan 2026 10:00:30 +0000",
    "From: alice@example.com",
    "From: alice@attacker.net",
    "To: bob@example.com",
    "",
    "body",
    "",
  ].join("\n");

  it("parses the Received chain in delivery order", () => {
    const hops = parseReceivedChain(msg);
    expect(hops.length).toBe(2);
    expect(hops[0].fromHost).toBe("mail.attacker.net");
    expect(hops[1].byHost).toBe("mx.example.com");
  });

  it("flags duplicated critical headers", () => {
    const { findings } = auditHeaderChain(msg);
    expect(findings.some((f) => f.kind === "duplicate-critical-header" && f.message.includes("from"))).toBe(true);
  });

  it("flags reversed timestamps", () => {
    const reversed = [
      "Received: from mx2.isp.net (mx2.isp.net [198.51.100.9])",
      "\tby mx.example.com with ESMTP id abc1",
      "\tfor <bob@example.com>; Fri, 02 Jan 2026 10:00:00 +0000",
      "Received: from mail.attacker.net (mail.attacker.net [203.0.113.1])",
      "\tby mx2.isp.net with ESMTP id xyz9",
      "\tfor <bob@example.com>; Fri, 02 Jan 2026 10:01:00 +0000",
      "From: alice@example.com",
      "To: bob@example.com",
      "",
      "body",
      "",
    ].join("\n");
    const { findings } = auditHeaderChain(reversed);
    expect(findings.some((f) => f.kind === "timestamp-reversal")).toBe(true);
  });
});

describe("attachment engine", () => {
  it("flags double extensions", () => {
    const findings = assessAttachment({ name: "invoice.pdf.exe", contentType: "", size: 10 });
    expect(findings.some((f) => f.kind === "double-extension")).toBe(true);
  });

  it("flags magic-byte mismatch", () => {
    const findings = assessAttachment({
      name: "report.pdf",
      contentType: "application/pdf",
      size: 10,
      head: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]),
    });
    expect(findings.some((f) => f.kind === "magic-mismatch")).toBe(true);
  });

  it("flags encrypted zip from local header flags", () => {
    const findings = assessAttachment({
      name: "archive.zip",
      contentType: "",
      size: 10,
      head: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x01, 0x00]),
    });
    expect(findings.some((f) => f.kind === "encrypted-archive")).toBe(true);
  });

  it("flags macro-capable formats", () => {
    const findings = assessAttachment({ name: "macro.docm", contentType: "", size: 5 });
    expect(findings.some((f) => f.kind === "macro-capable")).toBe(true);
  });

  it("clean attachment yields no findings", () => {
    const findings = assessAttachment({ name: "notes.txt", contentType: "text/plain", size: 5 });
    expect(findings.length).toBe(0);
  });

  it("counts severities", () => {
    const { highCount, warningCount } = assessAttachmentSurface([
      { name: "a.pdf.exe", contentType: "", size: 1 },
      { name: "b.txt", contentType: "", size: 1 },
    ]);
    expect(highCount).toBeGreaterThanOrEqual(1);
  });
});

describe("link engine", () => {
  it("flags anchor-href mismatch", () => {
    const findings = assessLink({
      href: "https://attacker.net/claim",
      anchorText: "https://example.com/claim",
    });
    expect(findings.some((f) => f.kind === "anchor-href-mismatch")).toBe(true);
  });

  it("flags punycode hosts", () => {
    const findings = assessLink({ href: "https://xn--e1awd7f.com/", anchorText: "example.com" });
    expect(findings.some((f) => f.kind === "punycode-host")).toBe(true);
  });

  it("flags redirector patterns", () => {
    const findings = assessLink({ href: "https://tracker.net/r?url=https%3A%2F%2Fexample.com" });
    expect(findings.some((f) => f.kind === "redirector-pattern")).toBe(true);
  });

  it("flags lookalike hosts against expected senders", () => {
    const findings = assessLink(
      { href: "https://examp1e.com/login", anchorText: "Sign in" },
      ["billing@example.com"]
    );
    expect(findings.some((f) => f.kind === "lookalike-host")).toBe(true);
  });

  it("clean link yields no findings", () => {
    const findings = assessLink({ href: "https://example.com/help", anchorText: "Help" });
    expect(findings.length).toBe(0);
  });

  it("never fetches: the engine is synchronous over strings", () => {
    const { findings } = assessLinkSurface([{ href: "https://example.com/x" }]);
    expect(findings.length).toBe(0);
  });
});
