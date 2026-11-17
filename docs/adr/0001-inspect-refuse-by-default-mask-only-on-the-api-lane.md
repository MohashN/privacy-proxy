---
status: accepted
---

# Inspect every request, refuse by default, mask only on the API lane

The proxy started as one household's way out to a cloud model, under that household's own
rule that it "inspects and blocks; it does not rewrite". As a public project it serves other
Operators, some of them teams whose apps would rather lose a phone number than a whole
request. **Decision:** the proxy inspects every request on both lanes. A Detection ends in a
Refusal unless the Policy file says Masking for that Detector. Masking is one-way, so the reply
keeps the Placeholder, and it applies only on the API lane: the Subscription lane always
refuses, whatever the Policy file says, and the proxy says so at startup. The proxy fails
closed: a scan it can't finish, a body it can't read, or the proxy itself being down means
no request goes out. It logs a Detection's kind, never its text, and never falls back to
another provider.

**Considered:**
- **Refuse only, as before.** This is the safest option and keeps requests byte for byte. It was
  rejected because API-lane apps, such as a support bot reading customer messages, would fail
  on every message that carries a phone number, with nobody there to edit and resend.
- **Masking on both lanes.** Anthropic's gateway guidance is to "inspect without modifying"
  ([LLM gateway protocol](https://code.claude.com/docs/en/llm-gateway-protocol), read
  2026-10-26). Claude Code resends its whole history every turn, its thinking blocks are signed,
  and prompt caching needs an identical prefix. A coding agent's edit would also name a
  Placeholder that isn't in the file.
- **Two-way masking (restore the original in the reply).** It needs a per-conversation mapping
  held in memory, and restores that survive stream chunk boundaries and tool calls. It is
  deferred until an Operator needs Masking for agent traffic.

**Consequences:**
- A fresh install refuses on every Detector. Masking is something an Operator turns on, one
  Detector at a time.
- An Operator can run stricter than the default (for example Refusal only, phones off with a
  Deny-list instead), to meet a household's own stricter rule.
- A Detector that might be slow (the planned local-model Detector) inherits fail-closed: if it
  runs out of time, the request is refused.
