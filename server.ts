import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import type Database from "better-sqlite3";
import { parseMessage } from "./lib/envelope/parse.js";
import { runAuthenticate, MAILAUTH_VERSION, computeDmarcAlignment } from "./lib/envelope/auth.js";
import { assessSpoofing } from "./lib/envelope/spoofing.js";
import { auditHeaderChain } from "./lib/envelope/headers.js";
import { assessAttachmentSurface } from "./lib/envelope/attachments.js";
import { assessLinkSurface } from "./lib/envelope/links.js";
import { screenDomainPosture } from "./lib/envelope/posture.js";
import { PinningDns } from "./lib/envelope/dns.js";
import {
  EnvelopeReport,
  canonicalPayload,
  getSignerAddress,
  reportDigest,
  requireSigner,
  signDigest,
  verifySignature,
} from "./lib/envelope/report.js";
import { getArtifact, saveArtifact } from "./lib/envelope/store.js";
import { anchorToOgStorage } from "./lib/og/storage.js";
import { FREE_TOOL_NAMES, TOOL_PRICES_ATOMIC, TOOL_PRICES_HUMAN } from "./lib/x402/challenge.js";

function textResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function validationError(message: string) {
  return textResult({ ok: false, error: message });
}

function usageFor(tool: string, description: string, fields: Record<string, string>): Record<string, unknown> {
  return {
    ok: false,
    tool,
    usage: description,
    fields,
    hint: "Every field is optional; supply at least one to get an answer.",
  };
}

function normalizeText(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.trim();
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v.length > 0);
}

const TRANSPORT_CAVEAT =
  "Envelope proves authenticity of transport, never intent or safety — a message from a genuine but compromised account passes every check here.";

function verdictNotes(verdict: string, finding: string, extra: string[] = []): string[] {
  return [TRANSPORT_CAVEAT, ...extra];
}

const MSG = "The raw RFC 5322 message.";

export function createEnvelopeServer(db: Database.Database) {
  const INSTRUCTIONS = `EVIDIQ Envelope MCP — cryptographic verification of inbound messages. 18 tools (8 free, 10 paid).

Free tools (always 200): envelope_capabilities, estimate_cost, validate_message_input, parse_message_structure, explain_auth_result, check_dns_txt, verify_envelope_report, get_artifact.

Paid tools (x402-gated, USDT0 on eip155:196): verify_dkim (0.005), check_dmarc_alignment (0.005), verify_message_auth (0.01), validate_arc_chain (0.01), detect_sender_spoofing (0.015), audit_header_chain (0.015), assess_attachment_surface (0.02), assess_link_surface (0.02), screen_domain_posture (0.02), attest_message_verdict (0.03).

Claim limits: Envelope proves authenticity of transport, never intent or safety. Absence is not evidence — no DKIM signature does not mean forged; a valid signature does not mean safe. Envelope never fetches a URL found in a message, never opens or extracts an attachment, never sends mail, and never persists the raw message — artifacts hold hashes, findings and pinned DNS answers. DNS answers are pinned into every report; libraryVersion is part of the digest so an upgrade that changes a verdict is visible. No model is anywhere in the verdict path — verification is arithmetic.`;

  const handler = createMcpHandler(
    (server) => {
      // ── FREE 1: envelope_capabilities ───────────────────────────────────
      server.registerTool(
        "envelope_capabilities",
        {
          title: "Envelope capabilities: tools, prices and claim limits",
          description:
            "Everything a buyer needs to decide: all 18 tools with prices, what each check proves and does NOT prove, and the claim limits. Free.",
          inputSchema: {},
        },
        async () => {
          const tools = [
            ...Object.entries(TOOL_PRICES_HUMAN).map(([name, price]) => ({ name, price, paid: true })),
            ...FREE_TOOL_NAMES.map((name) => ({ name, price: "free", paid: false })),
          ];
          return textResult({
            ok: true,
            service: "EVIDIQ Envelope — inbound message authenticity (MCP #19)",
            tools,
            claimLimits: [
              "authenticity of transport, never intent or safety",
              "absence is not evidence (no signature != forged; valid signature != safe)",
              "never fetches a URL found in a message",
              "never opens, extracts or executes an attachment",
              "never sends mail, never contacts the sender",
              "raw message is processed in memory and never persisted",
              "DNS answers pinned into every report",
              "no model in the verdict path",
            ],
            boundaries: {
              bulwark: "what the text says — if Envelope sees instruction-shaped content it points to Bulwark",
              circuit: "HMAC signatures on API webhooks — Envelope does not touch webhook signing",
              redact: "Envelope neither redacts nor stores the message",
            },
          });
        },
      );

      // ── FREE 2: estimate_cost ───────────────────────────────────────────
      server.registerTool(
        "estimate_cost",
        {
          title: "Exact price of any paid tool",
          description:
            "Exact atomic and human price for any paid tool, from the same table the gate charges from. Never invents an answer: an unknown tool name is an error. Free.",
          inputSchema: {
            tool: z.string().optional().describe("Paid tool name, e.g. verify_message_auth."),
          },
        },
        async (args: Record<string, unknown>) => {
          const tool = normalizeText(args.tool);
          if (!tool) {
            return textResult(usageFor("estimate_cost", "Exact atomic and human price for any paid tool.", { tool: "Paid tool name." }));
          }
          const atomic = TOOL_PRICES_ATOMIC[tool];
          if (!atomic) {
            return validationError(`unknown tool "${tool}" — estimate_cost only knows the ten paid tools`);
          }
          return textResult({
            ok: true,
            tool,
            amountAtomic: atomic,
            amountHuman: TOOL_PRICES_HUMAN[tool],
            chain: "eip155:196",
            token: "USDT0",
          });
        },
      );

      // ── FREE 3: validate_message_input ──────────────────────────────────
      server.registerTool(
        "validate_message_input",
        {
          title: "Resolve whether a message can be verified, before paying",
          description:
            "Is this parseable as a message, which authentication headers are present, and which paid checks would therefore be able to run — before anything is paid for. Free.",
          inputSchema: {
            message: z.string().optional().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) {
            return textResult(usageFor("validate_message_input", "Parseability and which paid checks can run.", { message: MSG }));
          }
          const parsed = await parseMessage(message);
          if (!parsed.ok) {
            return textResult({ ok: false, finding: "message cannot be parsed — no paid check would run; this is not evidence of forgery", messageHash: parsed.messageHash });
          }
          const inv = parsed.headerInventory;
          const hasDkim = (inv["dkim-signature"] ?? 0) > 0;
          const hasArc = Object.keys(inv).some((k) => k.startsWith("arc-"));
          const canRun: string[] = [];
          if (hasDkim) canRun.push("verify_dkim (0.005)");
          canRun.push("check_dmarc_alignment (0.005)");
          canRun.push("verify_message_auth (0.01)");
          if (hasArc) canRun.push("validate_arc_chain (0.01)");
          canRun.push("detect_sender_spoofing (0.015)");
          if (parsed.receivedCount > 0) canRun.push("audit_header_chain (0.015)");
          if (parsed.attachmentNames.length > 0) canRun.push("assess_attachment_surface (0.02)");
          if (parsed.linkCount > 0) canRun.push("assess_link_surface (0.02)");
          canRun.push("screen_domain_posture (0.02)");
          canRun.push("attest_message_verdict (0.03)");
          return textResult({
            ok: true,
            finding: hasDkim || hasArc
              ? "message is signed or ARC-chained; authentication checks can run"
              : "message carries no authentication headers — checks will report absence, which is not evidence of forgery",
            messageHash: parsed.messageHash,
            headersPresent: Object.keys(inv).filter((k) =>
              ["from", "to", "subject", "date", "message-id", "reply-to", "return-path", "received", "dkim-signature", "received-spf", "authentication-results"].includes(k)
            ),
            canRun,
          });
        },
      );

      // ── FREE 4: parse_message_structure ─────────────────────────────────
      server.registerTool(
        "parse_message_structure",
        {
          title: "MIME tree and header inventory, structure only",
          description:
            "Header inventory, attachment names and declared types, link count, body size. Structure only — no verdict, no content analysis. Free.",
          inputSchema: {
            message: z.string().optional().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) {
            return textResult(usageFor("parse_message_structure", "MIME tree and header inventory, structure only.", { message: MSG }));
          }
          const parsed = await parseMessage(message);
          if (!parsed.ok) return textResult(parsed);
          return textResult({
            ok: true,
            structureOnly: true,
            messageHash: parsed.messageHash,
            rawLength: parsed.rawLength,
            headerCount: parsed.headerCount,
            headerInventory: parsed.headerInventory,
            from: parsed.from,
            replyTo: parsed.replyTo,
            returnPath: parsed.returnPath,
            subject: parsed.subject,
            messageId: parsed.messageId,
            receivedCount: parsed.receivedCount,
            attachments: parsed.attachmentNames,
            linkCount: parsed.linkCount,
            bodyLength: parsed.bodyLength,
          });
        },
      );

      // ── FREE 5: explain_auth_result ─────────────────────────────────────
      server.registerTool(
        "explain_auth_result",
        {
          title: "Plain-language meaning of an authentication result code",
          description:
            "What a result code such as 'dkim=fail (body hash mismatch)' means, and what it does NOT prove. Free.",
          inputSchema: {
            code: z.string().optional().describe("Result code, e.g. dkim=fail (body hash mismatch)."),
          },
        },
        async (args: Record<string, unknown>) => {
          const code = normalizeText(args.code);
          if (!code) {
            return textResult(usageFor("explain_auth_result", "Plain-language meaning of a result code.", { code: "e.g. dkim=fail (body hash mismatch)" }));
          }
          const lower = code.toLowerCase();
          const explanations: Record<string, string> = {
            "dkim=pass": "The DKIM signature verified: the message was signed with a key published in the sender's DNS, and the body and signed headers are intact.",
            "dkim=fail": "A DKIM signature is present but does not verify (signature mismatch). The message was either altered after signing or the signature is not genuine.",
            "dkim=neutral": "A DKIM signature is present but could not be fully verified (for example body hash did not verify, or the key could not be retrieved). It is not a pass.",
            "dkim=none": "No DKIM signature on the message. This is NOT evidence of forgery — many legitimate senders do not sign.",
            "spf=pass": "The envelope sender's domain authorises the connecting IP. It says nothing about the From header.",
            "spf=fail": "The connecting IP is not authorised by the envelope domain — often a sign of spoofing, but legitimate forwarding can also cause it.",
            "spf=neutral": "The SPF record exists but declares neither pass nor fail for this IP.",
            "spf=softfail": "The SPF record says the IP is probably not authorised — treated as not passing.",
            "dmarc=pass": "The message passed DMARC: at least one of DKIM or SPF passed AND is aligned with the From domain.",
            "dmarc=fail": "Neither DKIM nor SPF was both passing and aligned with the From domain. Delivery policies (quarantine/reject) apply to such mail.",
            "dmarc=none": "No DMARC record exists for the From domain — nothing to enforce, and that is not evidence of authenticity.",
            "arc=pass": "The ARC chain is intact: the forwarding history is verifiable, so the original authentication results can be trusted.",
            "arc=fail": "The ARC chain does not validate — the forwarding history cannot be trusted as-is.",
            "arc=none": "No ARC chain present — normal for directly delivered mail.",
          };
          for (const [key, text] of Object.entries(explanations)) {
            if (lower.startsWith(key)) {
              return textResult({
                ok: true,
                code,
                meaning: text,
                doesNotProve: "A pass proves the transport path, never the intent or safety of the content. A genuine but compromised account passes every check.",
              });
            }
          }
          return validationError(`unknown result code "${code}" — examples: dkim=fail (body hash mismatch), dmarc=fail, arc=pass`);
        },
      );

      // ── FREE 6: check_dns_txt ───────────────────────────────────────────
      server.registerTool(
        "check_dns_txt",
        {
          title: "Raw SPF, DKIM-selector and DMARC records for a domain",
          description:
            "Raw TXT records for a domain: SPF, a DKIM selector, DMARC. No verdict, no alignment logic. The records are pinned into the answer. Free.",
          inputSchema: {
            domain: z.string().optional().describe("The domain to query, e.g. example.com."),
            selector: z.string().optional().describe("Optional DKIM selector, e.g. default."),
          },
        },
        async (args: Record<string, unknown>) => {
          const domain = normalizeText(args.domain);
          if (!domain) {
            return textResult(usageFor("check_dns_txt", "Raw SPF, DKIM-selector and DMARC records.", { domain: "Domain to query.", selector: "Optional DKIM selector." }));
          }
          const dns = new PinningDns();
          const out: Record<string, string[] | null> = {};
          const query = async (name: string): Promise<string[] | null> => {
            try {
              const txts = await dns.query(name, "TXT");
              return txts.length > 0 ? txts : null;
            } catch {
              return null;
            }
          };
          out[`${domain} (TXT)`] = await query(domain);
          out[`_dmarc.${domain} (TXT)`] = await query(`_dmarc.${domain}`);
          const selector = normalizeText(args.selector) || "default";
          out[`${selector}._domainkey.${domain} (TXT)`] = await query(`${selector}._domainkey.${domain}`);
          return textResult({
            ok: true,
            records: out,
            pinnedDns: dns.getPinned(),
            note: "raw records only — no verdict. Absence of a record is not evidence of forgery.",
          });
        },
      );

      // ── FREE 7: verify_envelope_report ──────────────────────────────────
      server.registerTool(
        "verify_envelope_report",
        {
          title: "Verify a report's digest and EIP-191 signature",
          description:
            "Recompute the JCS digest over the closed field set and EIP-191-verify the signature against the expected signer. Verification is never charged. Free.",
          inputSchema: {
            report: z.any().optional().describe("The report object as returned by a paid tool."),
            digest: z.string().optional().describe("The digest to verify (0x-prefixed)."),
            signature: z.string().optional().describe("The 0x EIP-191 signature."),
            signer: z.string().optional().describe("The expected signer address."),
          },
        },
        async (args: Record<string, unknown>) => {
          const report = args.report as EnvelopeReport | undefined;
          const digest = normalizeText(args.digest);
          const signature = normalizeText(args.signature);
          const signer = normalizeText(args.signer);

          if (!report && (!digest || !signature || !signer)) {
            return textResult(
              usageFor("verify_envelope_report", "Verify a report's digest and signature.", {
                report: "Report object as returned by a paid tool.",
                digest: "0x digest.",
                signature: "0x EIP-191 signature.",
                signer: "Expected signer address.",
              }),
            );
          }

          const computed = report ? reportDigest(report) : digest;
          let signatureValid = false;
          let expectedSigner: string | null = null;
          if (signature && signer) {
            signatureValid = await verifySignature(computed, signature as `0x${string}`, signer as `0x${string}`);
            expectedSigner = signer;
          }
          const fleetSigner = getSignerAddress();
          const knownToThisService = getArtifact(db, computed) !== null;
          return textResult({
            ok: true,
            digest: computed,
            recomputedFromReport: !!report,
            signatureValid,
            expectedSigner,
            fleetSigner,
            knownToThisService,
            caveat: TRANSPORT_CAVEAT,
          });
        },
      );

      // ── FREE 8: get_artifact ────────────────────────────────────────────
      server.registerTool(
        "get_artifact",
        {
          title: "Retrieve a stored attestation by digest",
          description:
            "Retrieves a previously attested verdict by its digest, including signature, signer and 0G anchor if present. Free.",
          inputSchema: {
            digest: z.string().optional().describe("The report digest to retrieve."),
          },
        },
        async (args: Record<string, unknown>) => {
          const digest = normalizeText(args.digest);
          if (!digest) {
            return textResult(usageFor("get_artifact", "Retrieve a stored attestation by digest.", { digest: "0x report digest." }));
          }
          const artifact = getArtifact(db, digest);
          if (!artifact) {
            return validationError(`no stored artifact for digest ${digest}`);
          }
          return textResult({ ok: true, artifact });
        },
      );

      // ── PAID 9: verify_dkim ─────────────────────────────────────────────
      server.registerTool(
        "verify_dkim",
        {
          title: "Verify every DKIM signature on the message",
          description:
            "Verifies every DKIM signature: canonicalisation, body hash, key retrieval, algorithm, expiry — per signature, with the reason for each failure. DNS answers pinned. Costs 0.005 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const { result, dns } = await runAuthenticate(message);
          const perSignature = result.dkim.results.map((r) => ({
            signingDomain: r.signingDomain,
            selector: r.selector ?? null,
            algorithm: r.algorithm ?? null,
            canonicalization: r.canonicalization ?? null,
            result: r.status.result,
            alignedToFrom: r.status.aligned ?? null,
            reason: r.status.comment ?? null,
          }));
          const passCount = perSignature.filter((s) => s.result === "pass").length;
          const signed = perSignature.length > 0;
          const checks = { dkim: perSignature };
          const verdict = signed
            ? passCount > 0
              ? "signed-and-verifying"
              : "signed-but-not-verifying"
            : "not-signed";
          const finding = signed
            ? `${passCount}/${perSignature.length} signatures verify`
            : "no DKIM signature — that is not evidence of forgery";
          const parsed = await parseMessage(message);
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: { verdict, finding, notes: verdictNotes(verdict, finding) },
            pinnedDns: dns.getPinned(),
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdict: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "pinned_dns",
          });
        },
      );

      // ── PAID 10: check_dmarc_alignment ──────────────────────────────────
      server.registerTool(
        "check_dmarc_alignment",
        {
          title: "DMARC policy and identifier alignment for the From domain",
          description:
            "Retrieves the DMARC policy for the From domain and reports identifier alignment against DKIM d= and the SPF domain, strict or relaxed — computed per RFC 7489. Costs 0.005 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const { result, dns } = await runAuthenticate(message);
          const fromDomain = result.dkim.headerFrom?.[0]?.split("@").pop() ?? null;
          const dmarc = result.dmarc;
          const alignment = computeDmarcAlignment(result, dmarc && typeof dmarc.rr === "string" ? dmarc.rr : undefined);
          const checks = {
            dmarc: dmarc
              ? { status: dmarc.status.result, policy: dmarc.policy, record: dmarc.rr ?? null, comment: dmarc.status.comment ?? null }
              : null,
            alignment,
          };
          const verdict = !fromDomain
            ? "no-from-domain"
            : !dmarc
              ? "no-dmarc-policy"
              : alignment.aligned
                ? "dmarc-aligned"
                : "dmarc-not-aligned";
          const finding = !fromDomain
            ? "no From domain to evaluate"
            : !dmarc
              ? `no DMARC record for ${fromDomain} — nothing to enforce, and that is not evidence of authenticity`
              : alignment.aligned
                ? `DMARC ${alignment.dkimAligned ? "DKIM" : "SPF"} aligned (${alignment.adkim}) — message passes DMARC`
                : `neither DKIM nor SPF aligns with ${fromDomain} under ${alignment.adkim} — message fails DMARC`;
          const parsed = await parseMessage(message);
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: {
              verdict,
              finding,
              notes: verdictNotes(verdict, finding, [
                "RFC 7489 alignment computed by Envelope (mailauth's strict alignment deviates — see README §6 findings)",
              ]),
            },
            pinnedDns: dns.getPinned(),
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdict: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "pinned_dns",
          });
        },
      );

      // ── PAID 11: verify_message_auth ────────────────────────────────────
      server.registerTool(
        "verify_message_auth",
        {
          title: "Composite verdict: SPF, DKIM, DMARC and alignment",
          description:
            "The composite verdict: SPF, DKIM, DMARC and alignment in one call, with the pinned DNS records behind it. The tool most callers want. Costs 0.01 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const { result, dns } = await runAuthenticate(message);
          const fromDomain = result.dkim.headerFrom?.[0]?.split("@").pop() ?? null;
          const dmarcRecord = result.dmarc && typeof result.dmarc.rr === "string" ? result.dmarc.rr : undefined;
          const alignment = computeDmarcAlignment(result, dmarcRecord);

          const dkim = result.dkim.results.map((r) => ({
            signingDomain: r.signingDomain,
            selector: r.selector ?? null,
            result: r.status.result,
            reason: r.status.comment ?? null,
          }));
          const spf = result.spf
            ? { domain: result.spf.domain ?? null, result: result.spf.status.result, record: result.spf.rr ?? null, comment: result.spf.status.comment ?? null }
            : null;
          const dmarc = result.dmarc
            ? { status: result.dmarc.status.result, policy: result.dmarc.policy ?? null, record: result.dmarc.rr ?? null, comment: result.dmarc.status.comment ?? null }
            : null;
          const arc = result.arc
            ? { status: result.arc.status.result, i: result.arc.i ?? null, comment: result.arc.status.comment ?? null }
            : null;

          const checks = { dkim, spf, dmarc, arc, alignment };
          const anyAuthHeader = result.dkim.results.length > 0 || !!result.spf || !!result.dmarc || !!result.arc;

          let verdict: string;
          let finding: string;
          if (!anyAuthHeader) {
            verdict = "nothing-to-verify";
            finding = "no authentication headers present — nothing to verify, and that is not evidence of forgery";
          } else if (dmarc && alignment.aligned) {
            verdict = "authenticated";
            finding = `message authenticates: DMARC-aligned ${alignment.dkimAligned ? "DKIM" : "SPF"} against ${fromDomain}`;
          } else if (dmarc && dmarc.status === "fail") {
            verdict = "not-authenticated";
            finding = `message does NOT authenticate: DMARC fails for ${fromDomain} (neither DKIM nor SPF aligned)`;
          } else if (dkim.some((d) => d.result === "pass")) {
            verdict = "partially-authenticated";
            finding = `DKIM verifies (${dkim.filter((d) => d.result === "pass").length} signature(s)) but DMARC does not pass — treat as suspicious`;
          } else if (spf && spf.result === "pass" && !alignment.spfAligned) {
            verdict = "partially-authenticated";
            finding = "SPF passes for the envelope domain but is unaligned with the From domain — the classic phish shape; do not read as safe";
          } else {
            verdict = "not-authenticated";
            finding = "no passing authentication evidence — absence of evidence is not evidence of forgery, but nothing here proves the sender";
          }

          const notes = verdictNotes(verdict, finding);
          if (verdict === "not-authenticated") {
            notes.push("absence is not evidence: no signature does not mean forged; a valid signature does not mean safe");
          }

          const parsed = await parseMessage(message);
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: { verdict, finding, notes },
            pinnedDns: dns.getPinned(),
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            verdict,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdictObj: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "pinned_dns",
          });
        },
      );

      // ── PAID 12: validate_arc_chain ─────────────────────────────────────
      server.registerTool(
        "validate_arc_chain",
        {
          title: "Validate the ARC chain on a forwarded message",
          description:
            "Validates the ARC chain so forwarded and mailing-list mail can be judged without treating every hop as a forgery. Costs 0.01 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const { result, dns } = await runAuthenticate(message);
          const arc = result.arc;
          const checks = {
            arc: arc
              ? { status: arc.status.result, i: arc.i ?? null, comment: arc.status.comment ?? null, authResults: arc.authResults ?? null }
              : null,
            dkim: result.dkim.results.map((r) => ({ signingDomain: r.signingDomain, result: r.status.result, reason: r.status.comment ?? null })),
          };
          const verdict = !arc || arc.status.result === "none"
            ? "no-arc-chain"
            : arc.status.result === "pass"
              ? "arc-valid"
              : "arc-invalid";
          const finding = !arc || arc.status.result === "none"
            ? "no ARC chain present — normal for directly delivered mail"
            : arc.status.result === "pass"
              ? `ARC chain validates (i=${arc.i}); the forwarding history is trustworthy`
              : `ARC chain does not validate: ${arc.status.comment ?? arc.status.result}`;
          const parsed = await parseMessage(message);
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: { verdict, finding, notes: verdictNotes(verdict, finding) },
            pinnedDns: dns.getPinned(),
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdict: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "pinned_dns",
          });
        },
      );

      // ── PAID 13: detect_sender_spoofing ─────────────────────────────────
      server.registerTool(
        "detect_sender_spoofing",
        {
          title: "Sender impersonation and lookalike detection",
          description:
            "Display-name impersonation, lookalike domains by homoglyph, punycode and edit distance against caller-supplied expected senders, plus Reply-To and Return-Path divergence. Costs 0.015 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
            expectedSenders: z.array(z.string()).optional().describe("Email addresses the sender plausibly claims to be, e.g. billing@acme.com."),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const parsed = await parseMessage(message);
          const expected = stringList(args.expectedSenders);
          const findings = assessSpoofing({
            from: parsed.from ?? "",
            fromDisplayName: parsed.fromDisplayName,
            replyTo: parsed.replyTo,
            returnPath: parsed.returnPath,
            expectedSenders: expected,
          });
          const high = findings.filter((f) => f.severity === "high").length;
          const verdict = high > 0 ? "spoofing-indicators" : findings.length > 0 ? "anomalies" : "no-indicators";
          const finding =
            high > 0
              ? `${high} high-severity spoofing indicator(s) found`
              : findings.length > 0
                ? `${findings.length} low-severity anomaly(ies) — review each`
                : "no spoofing indicators found in the structural analysis";
          const checks = { findings, from: parsed.from, fromDomain: parsed.fromDomain, replyTo: parsed.replyTo ?? null, returnPath: parsed.returnPath ?? null, expectedSenders: expected };
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: {
              verdict,
              finding,
              notes: verdictNotes(verdict, finding, [
                "structural analysis only — no DNS, no verdict on transport authentication; run verify_message_auth for that",
              ]),
            },
            pinnedDns: [],
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            verdict,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdictObj: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "structural",
          });
        },
      );

      // ── PAID 14: audit_header_chain ─────────────────────────────────────
      server.registerTool(
        "audit_header_chain",
        {
          title: "Received-chain forensics",
          description:
            "Hop consistency, timestamp ordering, injected or duplicated critical headers, gaps that indicate a forged path. Costs 0.015 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const { hops, findings, headerInventory } = auditHeaderChain(message);
          const high = findings.filter((f) => f.severity === "high").length;
          const verdict = high > 0 ? "chain-anomalies" : "no-anomalies";
          const finding =
            high > 0
              ? `${high} high-severity header-chain anomaly(ies)`
              : `Received chain of ${hops.length} hop(s) is internally consistent`;
          const parsed = await parseMessage(message);
          const checks = { hops, findings, headerInventory };
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: { verdict, finding, notes: verdictNotes(verdict, finding) },
            pinnedDns: [],
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            verdict,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdictObj: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "structural",
          });
        },
      );

      // ── PAID 15: assess_attachment_surface ──────────────────────────────
      server.registerTool(
        "assess_attachment_surface",
        {
          title: "Structural risk of attachments, without opening them",
          description:
            "Extension against magic bytes, double extensions, macro-capable formats, archive nesting depth, encrypted archives. Nothing is decompressed beyond header inspection. Costs 0.02 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
            attachmentNames: z.array(z.string()).optional().describe("Explicit attachment file names, if the message cannot be parsed."),
            attachmentHeads: z.array(z.string()).optional().describe("Hex-encoded first bytes of each attachment (optional)."),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const parsed = await parseMessage(message);
          const names = stringList(args.attachmentNames);
          const attachments = (names.length > 0 ? names : parsed.attachmentNames.map((a) => a.name)).map((name, i) => {
            const headRaw = Array.isArray(args.attachmentHeads) ? args.attachmentHeads[i] : undefined;
            let head: Uint8Array | undefined;
            if (typeof headRaw === "string" && headRaw.length >= 2 && headRaw.length % 2 === 0) {
              try {
                head = new Uint8Array(Buffer.from(headRaw, "hex"));
              } catch {
                head = undefined;
              }
            }
            return { name, contentType: "", size: 0, head };
          });
          const { findings, highCount, warningCount } = assessAttachmentSurface(attachments);
          const verdict = highCount > 0 ? "risky-attachments" : warningCount > 0 ? "caution" : "no-risk-indicators";
          const finding = attachments.length === 0
            ? "no attachments to assess"
            : highCount > 0
              ? `${highCount} high-severity attachment risk(s) across ${attachments.length} attachment(s)`
              : warningCount > 0
                ? `${warningCount} warning(s) — review each`
                : `${attachments.length} attachment(s) with no structural risk indicators`;
          const checks = { attachments, findings };
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: {
              verdict,
              finding,
              notes: verdictNotes(verdict, finding, ["structural analysis only — Envelope never opens, extracts or executes an attachment"]),
            },
            pinnedDns: [],
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            verdict,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdictObj: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "structural",
          });
        },
      );

      // ── PAID 16: assess_link_surface ────────────────────────────────────
      server.registerTool(
        "assess_link_surface",
        {
          title: "Structural link analysis, without fetching",
          description:
            "Punycode hosts, anchor text disagreeing with href, credential-shaped URLs, redirector patterns, lookalike hosts. Nothing is fetched. Costs 0.02 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
            expectedSenders: z.array(z.string()).optional().describe("Email addresses the sender plausibly claims to be, for lookalike host checks."),
            links: z.array(z.any()).optional().describe("Explicit {href, anchorText} pairs if the message cannot be parsed."),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const parsed = await parseMessage(message);
          const expected = stringList(args.expectedSenders);
          const explicitLinks = Array.isArray(args.links)
            ? args.links
                .filter((l): l is Record<string, unknown> => typeof l === "object" && l !== null)
                .map((l) => ({ href: String(l.href ?? ""), anchorText: l.anchorText ? String(l.anchorText) : undefined }))
                .filter((l) => l.href.length > 0)
            : [];
          const links =
            explicitLinks.length > 0
              ? explicitLinks
              : (message.match(/https?:\/\/[^\s<>"')]+/g) ?? []).map((href) => ({ href }));
          const { findings, highCount, warningCount } = assessLinkSurface(links, expected);
          const verdict = highCount > 0 ? "risky-links" : warningCount > 0 ? "caution" : "no-risk-indicators";
          const finding = links.length === 0
            ? "no links to assess"
            : highCount > 0
              ? `${highCount} high-severity link risk(s) across ${links.length} link(s)`
              : warningCount > 0
                ? `${warningCount} warning(s) — review each`
                : `${links.length} link(s) with no structural risk indicators`;
          const checks = { links, findings };
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: {
              verdict,
              finding,
              notes: verdictNotes(verdict, finding, ["structural analysis only — Envelope never fetches a URL found in a message"]),
            },
            pinnedDns: [],
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            verdict,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdictObj: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "structural",
          });
        },
      );

      // ── PAID 17: screen_domain_posture ──────────────────────────────────
      server.registerTool(
        "screen_domain_posture",
        {
          title: "Sender-domain posture: SPF, DKIM selectors, DMARC, DNSSEC, MX",
          description:
            "SPF record validity and lookup count, resolvable DKIM selectors, DMARC policy strength, DNSSEC, MX presence. The DNS answers are pinned. Costs 0.02 USDT0.",
          inputSchema: {
            domain: z.string().describe("The sender domain, e.g. example.com."),
            dkimSelectors: z.array(z.string()).optional().describe("DKIM selectors to probe (defaults: default, selector1, k1, s1, mail, dkim)."),
          },
        },
        async (args: Record<string, unknown>) => {
          const domain = normalizeText(args.domain);
          if (!domain) return validationError("domain is required");
          const selectors = stringList(args.dkimSelectors);
          const result = await screenDomainPosture(domain, { dkimSelectors: selectors.length > 0 ? selectors : undefined });
          const high = result.findings.filter((f) => f.severity === "high").length;
          const verdict = high > 0 ? "weak-posture" : "no-critical-gaps";
          const finding = high > 0
            ? `${high} critical posture gap(s) for ${domain}`
            : `posture of ${domain}: SPF ${result.spf.record ? (result.spf.hardFail ? "valid with -all" : "present without -all") : "absent"}, DMARC ${result.dmarc.policy ?? "absent"}, DNSSEC ${result.dnssec ? "present" : "absent"}`;
          const report: EnvelopeReport = {
            messageHash: `domain:${domain}`,
            checks: { spf: result.spf, dkim: result.dkim, dmarc: result.dmarc, dnssec: result.dnssec, mx: result.mx, findings: result.findings },
            verdict: {
              verdict,
              finding,
              notes: verdictNotes(verdict, finding, [
                "posture is about the sender domain's own records — it does not authenticate any particular message; run verify_message_auth for that",
              ]),
            },
            pinnedDns: result.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          let signature: string | null = null;
          let signer: string | null = null;
          if (getSignerAddress()) {
            const signedReport = await signDigest(digest, requireSigner().privateKey);
            signature = signedReport.signature;
            signer = signedReport.signer;
          }
          saveArtifact(db, { digest, report, signature: signature ?? "", signer: signer ?? "", anchorRoot: null, anchorTx: null });
          return textResult({
            ok: true,
            verdict,
            finding,
            messageHash: report.messageHash,
            checks: report.checks,
            verdictObj: report.verdict,
            pinnedDns: report.pinnedDns,
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: report.verifiedAt,
            digest,
            signature,
            signer,
            basis: "pinned_dns",
          });
        },
      );

      // ── PAID 18: attest_message_verdict ─────────────────────────────────
      server.registerTool(
        "attest_message_verdict",
        {
          title: "EIP-191 signed, 0G-anchored attestation of a verification",
          description:
            "A verification for a message, JCS-digested, EIP-191 signed by the fleet signer, anchored to 0G Storage, and stored for later retrieval. The record that survives key rotation. Costs 0.03 USDT0.",
          inputSchema: {
            message: z.string().describe(MSG),
          },
        },
        async (args: Record<string, unknown>) => {
          const message = normalizeText(args.message);
          if (!message) return validationError("message is required");
          const { result, dns } = await runAuthenticate(message);
          const fromDomain = result.dkim.headerFrom?.[0]?.split("@").pop() ?? null;
          const dmarcRecord = result.dmarc && typeof result.dmarc.rr === "string" ? result.dmarc.rr : undefined;
          const alignment = computeDmarcAlignment(result, dmarcRecord);
          const dkim = result.dkim.results.map((r) => ({
            signingDomain: r.signingDomain,
            selector: r.selector ?? null,
            result: r.status.result,
            reason: r.status.comment ?? null,
          }));
          const spf = result.spf ? { domain: result.spf.domain ?? null, result: result.spf.status.result, record: result.spf.rr ?? null } : null;
          const dmarc = result.dmarc ? { status: result.dmarc.status.result, policy: result.dmarc.policy ?? null, record: result.dmarc.rr ?? null } : null;
          const arc = result.arc ? { status: result.arc.status.result, i: result.arc.i ?? null, comment: result.arc.status.comment ?? null } : null;
          const checks = { dkim, spf, dmarc, arc, alignment };
          const anyAuthHeader = result.dkim.results.length > 0 || !!result.spf || !!result.dmarc || !!result.arc;
          const verdict = !anyAuthHeader
            ? "nothing-to-verify"
            : dmarc && alignment.aligned
              ? "authenticated"
              : dmarc && dmarc.status === "fail"
                ? "not-authenticated"
                : dkim.some((d) => d.result === "pass")
                  ? "partially-authenticated"
                  : "not-authenticated";
          const finding = `verification verdict for ${fromDomain ?? "unknown domain"}: ${verdict}`;
          const parsed = await parseMessage(message);
          const report: EnvelopeReport = {
            messageHash: parsed.messageHash,
            checks,
            verdict: { verdict, finding, notes: verdictNotes(verdict, finding) },
            pinnedDns: dns.getPinned(),
            libraryVersion: MAILAUTH_VERSION,
            verifiedAt: new Date().toISOString(),
          };
          const digest = reportDigest(report);
          const { signature, signer } = await signDigest(digest, requireSigner().privateKey);
          let anchor: { status: string; root?: string; tx?: string; error?: string };
          try {
            const anchorResult = await anchorToOgStorage({ digest, report });
            if (anchorResult.ok) {
              anchor = { status: "anchored", root: anchorResult.root, tx: anchorResult.tx };
            } else {
              anchor = { status: "anchoring-failed", error: anchorResult.error };
            }
          } catch (err: any) {
            anchor = { status: "anchoring-failed", error: err.message ?? String(err) };
          }
          saveArtifact(db, { digest, report, signature, signer, anchorRoot: anchor.root ?? null, anchorTx: anchor.tx ?? null });
          return textResult({
            ok: true,
            digest,
            signature,
            signer,
            canonicalDigestInputs: canonicalPayload(report),
            anchor,
            report,
            artifactDigest: digest,
            basis: "pinned_dns",
          });
        },
      );
    },
  );

  return async (req: Request): Promise<Response> => {
    return handler(req);
  };
}
