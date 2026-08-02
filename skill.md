# EVIDIQ Envelope MCP

Cryptographic verification of inbound messages — service #19 of the EVIDIQ fleet.

**Bulwark reads what the message says. Envelope proves who sent it.**

- **18 tools** (8 free, 10 paid in USDT0 on eip155:196): `verify_dkim` (0.005),
  `check_dmarc_alignment` (0.005), `verify_message_auth` (0.01), `validate_arc_chain`
  (0.01), `detect_sender_spoofing` (0.015), `audit_header_chain` (0.015),
  `assess_attachment_surface` (0.02), `assess_link_surface` (0.02),
  `screen_domain_posture` (0.02), `attest_message_verdict` (0.03); free:
  `envelope_capabilities`, `estimate_cost`, `validate_message_input`,
  `parse_message_structure`, `explain_auth_result`, `check_dns_txt`,
  `verify_envelope_report`, `get_artifact`.
- **Transport authenticity, never intent:** a message from a genuine but compromised
  account passes every check. Absence is not evidence — no signature does not mean
  forged; a valid signature does not mean safe. Every verdict says so in its body.
- **Never a proxy:** Envelope never fetches a URL found in a message, never opens or
  extracts an attachment, never sends mail, never contacts the sender, and never
  persists the raw message — artifacts hold hashes, findings and pinned DNS answers.
- **Pinned DNS:** every report carries the DNS answers the verdict was derived from;
  `libraryVersion` is part of the digest, so an upgrade that changes a verdict is
  visible rather than silent. No model is anywhere in the verdict path.
- **Endpoint:** `POST https://mcp.evidiq.dev/envelope/mcp` (MCP streamable HTTP).
