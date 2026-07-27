# Exit & Continuity

**Publish this page.** A customer will not hand their entire company brain to a startup
without it, and every competitor's silence here is the opening.

| Feature | What it means |
|---|---|
| **Continuous mirror export** | every fact, transcript, ledger entry, rule and receipt streams to customer-owned storage in real time. **If Vault dies tonight, their memory is intact tomorrow morning.** |
| **Open documented format** | published JSON/JSONL schema, written into every export as `SCHEMA.md`. Not a proprietary blob. Portable to a competitor. |
| **Self-host escape hatch** | a run-anywhere build the customer stands up from their own mirror, without us. `SELFHOST.md` ships inside every export. |
| **Source-code escrow** | third-party escrow with defined release triggers: insolvency, acquisition without assumption, 30-day service failure, breach of continuity terms |
| **Ledger verifiable without us** | customer-held keys plus a standalone verifier. The proof survives our death. |
| **Free export, any time, any volume** | no egress charge, no throttling, no "contact sales" |
| **Migration both ways** | import from Mem0 / Zep / Letta / Glean / Smarsh; export to any of them |
| **Change-of-control commitments** | written: what happens to their data if we're acquired, including a termination right |
| **Concentration-risk statement** | a written answer to "what % of our AI operations depends on you" — because their insurer asks |
| **Business continuity disclosure** | runway, insurance, key-person coverage, under NDA to enterprise buyers who ask |

## Check it yourself

```bash
vault export ./out               # everything
node bin/vault-verify.js ./out   # verify it without us
vault doctor                     # tells you if the mirror is NOT configured
```

`vault doctor` reports an unconfigured mirror as a **high** finding, on purpose. A
continuity story that is switched off is not a continuity story.

## Contract terms, pre-agreed

Rather than discovering these in month four of a security review:

- No training on customer data, by default, flowed down to every upstream model
  provider with signed attestations
- Sub-processor disclosure with flow-down
- 90-day model-deprecation notice
- Change-of-law compliance maintenance
- AI-specific indemnity
- Audit rights on notice
- 30–60 day deletion with **written backup-purge confirmation**
- Named portability window and format
- Kill switch SLA with a named administrator

## The failure modes this is designed against

1. **We go under.** The mirror is already in your bucket, in a documented format, and
   the self-host build stands it back up. The ledger verifies with your key.
2. **We get acquired by someone you don't want.** Change-of-control termination right,
   plus everything in point 1.
3. **We have a bad outage.** The fail-safe posture is queue-and-drain or reject —
   never pass unchecked — and the mirror keeps streaming.
4. **You want to leave.** Free export, any volume, migration tooling into the
   competitor of your choice. No exit fee and no last-minute format surprise.
5. **Your auditor doesn't trust either of us.** That's what `bin/vault-verify.js` is
   for: it imports nothing from `src/` and recomputes everything from the export alone.

## Deployment models

Because "where does it run" is the other half of continuity.

| Model | For |
|---|---|
| Vault cloud, multi-tenant | mid-market, fast start |
| Vault cloud, single tenant | larger, isolation required |
| Bring Your Own Bucket | data in their storage, software in ours |
| Customer VPC | regulated, data can't leave their cloud |
| On-premise | finance, health, defence, government |
| Air-gapped | highest classification, offline updates |
| Hybrid | metadata in cloud, content on-prem |
| Hash-only | content never leaves at all |
| Sovereign region | in-country dedicated (India, EU, UK, Gulf, gov) |

The zero-dependency constraint exists for the bottom half of that table. From a fresh
clone, `node bin/vault.js serve` is the whole install — no registry, no build step, no
six-week procurement to add a database.
