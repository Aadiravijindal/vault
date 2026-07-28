# Vault Bug Bounty Programme

**Status:** published and in force.
**Version:** 1.0 — 2026-07-28.
**Contact:** security@vault.example (PGP fingerprint published at `/.well-known/security.txt`).

This programme needs no signature from anyone to be effective. It is a unilateral
undertaking by us, and it binds us from the date above.

---

## 1. Why there is a bounty class for one specific thing

Vault's central product claim is that **every write to the fact store passes
through the gate, and the gate cannot be turned off**. Not "is enabled by
default". Not "is enabled unless an administrator disables it". Cannot be turned
off, in any module configuration, with any third-party tool connected.

If that claim is false, the product is not what it says it is. So gate bypass is
the highest-paid class here, above remote code execution, and it is the one we
most want people to attack.

## 2. Scope

### In scope

| Target | Notes |
|---|---|
| The Vault engine (`src/`) | All twelve layers, all module states |
| The gate (`src/gate/`) — all ten checks | Including every detector class |
| The ledger and the standalone verifier (`bin/vault-verify.js`) | |
| The HTTP API and the MCP server | Every route, every role |
| The CLI (`bin/vault.js`) | |
| The control surface (`src/ui/`) | Including the PWA shell |
| Identity: SAML, OIDC, SCIM, sessions, MFA, break-glass | |
| Storage: encryption at rest, key management, crypto-shredding, backup/restore | |
| Connector clients (`src/connectors/`) | Auth, signature verification, replay windows |
| Module adapters and the Built-in/Connected/Both toggle | |

### Out of scope

- Third-party vendor products themselves (Okta, Salesforce, Langfuse and so on).
  Report those to the vendor. **A flaw in how *we* call them is in scope.**
- Denial of service by volume. We will not pay for "I sent a lot of requests".
  A *logic* DoS — one cheap request that costs the server unboundedly — is in scope.
- Social engineering of our staff or customers.
- Physical attacks.
- Missing security headers, or TLS configuration findings, with no demonstrated impact.
- Self-XSS, and clickjacking on pages with no state-changing action.
- Reports generated wholesale by a scanner with no demonstrated exploitability.
- Anything requiring a rooted or jailbroken device plus physical access.

## 3. Reward tiers

Paid in USD, by bank transfer, within 30 days of triage confirming the finding.

| Severity | Range | What qualifies |
|---|---|---|
| **Gate bypass** | **$25,000 – $50,000** | Any path that writes to the fact store without the gate running, in any module configuration. See §4. |
| Critical | $10,000 – $25,000 | RCE; authentication bypass; cross-tenant data access; recovering content after a crypto-shred; forging a ledger entry the standalone verifier accepts. |
| High | $4,000 – $10,000 | Privilege escalation; reading across a wall; break-glass self-grant or single-approver grant; erasure that leaves recoverable content; extracting a key. |
| Medium | $1,000 – $4,000 | Stored XSS with real impact; SSRF reaching internal services; a detector class evaded such that a known-malicious payload passes; leaking one tenant's metadata. |
| Low | $250 – $1,000 | Information disclosure of non-content metadata; a rate limit that can be bypassed; a logic flaw with limited impact. |

Ranges, not fixed amounts: the number within a range depends on exploitability,
the access required, and the blast radius. We publish our reasoning with the
award. If you disagree, say so — we have revised awards upward before and will
again.

**We pay for duplicates of *unfixed* findings at 25%** if your report adds
materially to our understanding of the issue.

## 4. The gate-bypass class, defined precisely

We pay the gate-bypass bounty for a reproducible demonstration that a fact
reached the live fact store without a complete gate evaluation, where the gate
would not have passed it. Specifically, any of:

1. A write path that never calls the gate.
2. A configuration — any of Built-in / Connected / Both, with any third-party
   adapter — in which the gate is skipped.
3. A payload that causes the gate to record a PASS verdict without having run
   one or more of the ten checks.
4. A way to make the gate fail open rather than queue or reject.
5. A path that writes to the store directly, going around the write path entirely,
   from any interface a customer or agent can reach.
6. Any means by which an administrator, break-glass session, or connector can
   disable the gate.

**Not** in this class: causing the gate to *block* something it should pass
(that is a bug, and we want it, but it is a correctness issue, not a bypass);
or a detector missing a novel payload (that is the Medium "detector evaded"
class unless it defeats the ensemble entirely).

## 5. Safe harbour

If you make a good-faith effort to comply with this policy while researching:

- **We will not initiate or support legal action against you**, under the
  Computer Fraud and Abuse Act, the Computer Misuse Act 1990, the DMCA §1201, any
  equivalent law in any jurisdiction, or under our terms of service.
- We will not report you to law enforcement for the research.
- If a third party brings action against you for activity conducted in
  compliance with this policy, **we will make it publicly known that your
  actions were authorised by us**, and we will say so in writing to that party
  and to any court that asks.
- We waive any claim that your research breached our acceptable use policy.

This safe harbour applies to *you*, personally, and to the organisation you
research on behalf of.

Good faith means, concretely:

- You do not access, modify, destroy or exfiltrate data belonging to anyone
  other than yourself or an account you were given for testing.
- If you encounter customer data, **you stop, you do not save a copy, and you
  tell us immediately**. Doing so does not disqualify you; concealing it does.
- You do not degrade service for others.
- You do not use a finding for any purpose other than demonstrating it to us.
- You give us the disclosure window in §7 before publishing.
- You do not extort. A report conditioned on payment before disclosure is not a
  bug report.

If you are unsure whether something is in bounds, ask first at
security@vault.example. Asking never counts against you.

## 6. How to report

Email **security@vault.example**, encrypted to our published PGP key if the
finding is sensitive. Include:

- A description of the issue and its impact.
- Reproduction steps precise enough for us to follow without guessing. A failing
  test against this repository is ideal and speeds triage considerably.
- The version or commit you tested.
- Whether you intend to publish, and when.

You will get a human reply, not an autoresponder.

## 7. Timeline

| Stage | Our commitment |
|---|---|
| Acknowledgement | 2 business days |
| Triage decision and severity | 10 business days |
| Fix for Critical / Gate bypass | 30 days |
| Fix for High | 60 days |
| Fix for Medium / Low | 90 days |
| Payment after triage confirmation | 30 days |
| Public disclosure | 90 days from report, or on fix, whichever is sooner |

**We will not ask you to delay disclosure beyond 90 days.** If we need longer
for a genuinely hard fix, we will ask, explain why, and accept your answer if it
is no. If we miss our own deadline, you are free to publish and we will not
treat it as a breach of this policy.

We will credit you by the name you choose, or not at all if you prefer.

## 8. Things we will not do

- Require an NDA as a condition of reporting or of payment.
- Require you to accept a payment that comes with a confidentiality clause.
- Use the bounty programme to buy silence about an issue we have not fixed.
- Reduce an award because a fix turned out to be easy.

## 9. What is deliberately not covered, and why

We publish our own known limits so nobody wastes effort rediscovering them, and
so nobody mistakes a documented trade-off for an undisclosed flaw. These are
**not** eligible for a bounty as they stand, because we already know:

- The ledger stays readable on disk by design, so the standalone verifier needs
  no key. It carries no customer content; operator-authored audit prose
  (`reason`, `note`, `matter`, `purpose`) is deliberately left readable so an
  auditor can read it. **Finding content in the ledger that is *not* in that
  category is in scope and we want it.**
- Ledger subject pseudonymisation is HMAC under a salt derived from the root
  key. Whoever holds the root key can confirm a guessed identifier. This is
  pseudonymisation, not anonymisation, and we say so.
- Records naming more than one person fall back to a namespace key, so a
  per-person crypto-shred does not reach them in backups. The erasure receipt
  states this per record rather than claiming blanket coverage.
- 70 of the 74 connector clients are verified against published vendor
  documentation rather than a live account, because our build environment cannot
  reach those hosts. Each `clientStatus()` names the credential needed.

---

*Reviewed on publication and at least annually. Changes are versioned; the
version in force when you reported is the version that applies to you.*
