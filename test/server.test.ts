import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createEnvelopeServer } from "../server.js";
import { openArtifactStore } from "../lib/envelope/store.js";
import { handleX402Gate } from "../lib/x402/gate.js";
import { buildMessage, generateKey, signWithDkim } from "./fixtures.js";

const TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // anvil #0 - throwaway, test-only

let dbDir: string;
let db: ReturnType<typeof openArtifactStore>;
let handler: (req: Request) => Promise<Response>;

beforeAll(async () => {
  process.env.ENVELOPE_SIGNER_PRIVATE_KEY = TEST_KEY;
  process.env.ENVELOPE_X402_BYPASS = "1";
  dbDir = await mkdtemp(join(tmpdir(), "envelope-test-"));
  db = openArtifactStore(join(dbDir, "test.db"));
  const inner = createEnvelopeServer(db);
  handler = (req) => handleX402Gate(req, inner);
});

afterAll(() => {
  delete process.env.ENVELOPE_SIGNER_PRIVATE_KEY;
  delete process.env.ENVELOPE_X402_BYPASS;
  db.close();
});

async function call(
  name: string,
  args: Record<string, unknown>
): Promise<{ status: number; body: any }> {
  const res = await handler(
    new Request("http://localhost/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    })
  );
  let body: any;
  try {
    body = await res.json();
  } catch {
    body = await res.text();
  }
  return { status: res.status, body };
}

async function textOf(res: { status: number; body: any }): Promise<any> {
  if (typeof res.body === "string") return JSON.parse(res.body);
  return JSON.parse(res.body.result.content[0].text);
}

const signedMsg = (async () => {
  const key = generateKey();
  return signWithDkim(
    buildMessage({
      from: "alice@example.com",
      fromDomain: "example.com",
      to: "bob@other.com",
      subject: "Invoice",
      body: "Settle the invoice.",
      clientIp: "203.0.113.1",
      clientHost: "mail.example.com",
    }),
    { signingDomain: "example.com", selector: "sel1", key }
  );
})();

describe("Envelope MCP server (bypass on)", () => {
  it("lists all 18 tools", async () => {
    const res = await handler(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      })
    );
    const body = await res.json();
    const tools = body.result.tools as { name: string }[];
    expect(tools.length).toBe(18);
    const names = tools.map((t) => t.name);
    for (const free of [
      "envelope_capabilities",
      "estimate_cost",
      "validate_message_input",
      "parse_message_structure",
      "explain_auth_result",
      "check_dns_txt",
      "verify_envelope_report",
      "get_artifact",
    ]) {
      expect(names).toContain(free);
    }
    for (const paid of [
      "verify_dkim",
      "check_dmarc_alignment",
      "verify_message_auth",
      "validate_arc_chain",
      "detect_sender_spoofing",
      "audit_header_chain",
      "assess_attachment_surface",
      "assess_link_surface",
      "screen_domain_posture",
      "attest_message_verdict",
    ]) {
      expect(names).toContain(paid);
    }
  });

  it("free tools answer bare {} with usage and 200", async () => {
    for (const name of [
      "envelope_capabilities",
      "estimate_cost",
      "validate_message_input",
      "parse_message_structure",
      "explain_auth_result",
      "check_dns_txt",
      "verify_envelope_report",
      "get_artifact",
    ]) {
      const res = await call(name, {});
      expect(res.status).toBe(200);
      const t = await textOf(res);
      expect(t.ok).toBeDefined();
    }
  });

  it("estimate_cost returns the exact price table", async () => {
    const t = await textOf(await call("estimate_cost", { tool: "verify_message_auth" }));
    expect(t.amountAtomic).toBe("10000");
    expect(t.amountHuman).toBe("0.01 USDT0");
  });

  it("validate_message_input resolves what can run, before paying", async () => {
    const t = await textOf(await call("validate_message_input", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(t.canRun).toContain("verify_dkim (0.005)");
  });

  it("parse_message_structure reports header inventory without content", async () => {
    const t = await textOf(await call("parse_message_structure", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(t.structureOnly).toBe(true);
    expect(t.headerInventory["dkim-signature"]).toBe(1);
    expect(t.rawMessage).toBeUndefined();
  });

  it("explain_auth_result explains a code and what it does not prove", async () => {
    const t = await textOf(await call("explain_auth_result", { code: "dkim=fail (body hash mismatch)" }));
    expect(t.ok).toBe(true);
    expect(t.meaning.length).toBeGreaterThan(10);
    expect(t.doesNotProve).toMatch(/never/);
  });

  it("verify_dkim returns per-signature results with pinned DNS and a signed report", async () => {
    const t = await textOf(await call("verify_dkim", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(Array.isArray(t.checks.dkim)).toBe(true);
    expect(Array.isArray(t.pinnedDns)).toBe(true);
    expect(t.libraryVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(t.digest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(t.signature).toMatch(/^0x/);
    expect(t.signer.toLowerCase()).toBe("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
  });

  it("verify_message_auth returns a composite verdict with caveats", async () => {
    const t = await textOf(await call("verify_message_auth", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(["authenticated", "not-authenticated", "partially-authenticated", "nothing-to-verify"]).toContain(t.verdict);
    expect(JSON.stringify(t.verdictObj.notes)).toMatch(/transport/);
  });

  it("check_dmarc_alignment recomputes RFC 7489 alignment itself", async () => {
    const t = await textOf(await call("check_dmarc_alignment", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(["strict", "relaxed"]).toContain(t.checks.alignment.adkim);
  });

  it("detect_sender_spoofing is structural", async () => {
    const t = await textOf(
      await call("detect_sender_spoofing", {
        message: await signedMsg,
        expectedSenders: ["alice@example.com"],
      })
    );
    expect(t.ok).toBe(true);
    expect(["spoofing-indicators", "anomalies", "no-indicators"]).toContain(t.verdict);
    expect(t.basis).toBe("structural");
  });

  it("audit_header_chain reports the Received chain", async () => {
    const t = await textOf(await call("audit_header_chain", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(Array.isArray(t.checks.hops)).toBe(true);
  });

  it("assess_attachment_surface flags a double extension", async () => {
    const t = await textOf(
      await call("assess_attachment_surface", {
        message: await signedMsg,
        attachmentNames: ["invoice.pdf.exe"],
      })
    );
    expect(t.ok).toBe(true);
    expect(t.verdict).toBe("risky-attachments");
    expect(JSON.stringify(t.checks.findings)).toMatch(/double-extension/);
  });

  it("assess_link_surface flags a lookalike host", async () => {
    const t = await textOf(
      await call("assess_link_surface", {
        message: await signedMsg,
        expectedSenders: ["billing@example.com"],
        links: [{ href: "https://examp1e.com/pay" }],
      })
    );
    expect(t.ok).toBe(true);
    expect(t.verdict).toBe("risky-links");
  });

  it("verify_envelope_report round-trips a paid report (digest + signature)", async () => {
    const paid = await textOf(await call("verify_dkim", { message: await signedMsg }));
    const t = await textOf(
      await call("verify_envelope_report", {
        digest: paid.digest,
        signature: paid.signature,
        signer: paid.signer,
      })
    );
    expect(t.signatureValid).toBe(true);
    expect(t.knownToThisService).toBe(true);
  });

  it("get_artifact retrieves the stored report by digest", async () => {
    const paid = await textOf(await call("verify_message_auth", { message: await signedMsg }));
    const t = await textOf(await call("get_artifact", { digest: paid.digest }));
    expect(t.ok).toBe(true);
    expect(t.artifact.digest).toBe(paid.digest);
    expect(t.artifact.report.messageHash).toBe(paid.messageHash);
  });

  it("attest_message_verdict signs and attempts anchoring (best effort)", async () => {
    const t = await textOf(await call("attest_message_verdict", { message: await signedMsg }));
    expect(t.ok).toBe(true);
    expect(t.digest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(t.signature).toMatch(/^0x/);
    expect(t.signer.toLowerCase()).toBe("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    expect(["anchored", "anchoring-failed"]).toContain(t.anchor.status);
    expect(t.report.libraryVersion).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("unknown tool name is an error, not a hang", async () => {
    const res = await call("no_such_tool", {});
    expect([200, 400, 404]).toContain(res.status);
  });
});
