# Operations

## Install

Node 22+. Nothing else.

```bash
git clone <repo> && cd vault
node bin/vault.js serve --port 8080 --data ./data
```

No `npm install`, no build step, no network access required. That is a deliberate
constraint: the product has to run on-prem and air-gapped, where "just add a database"
is a six-week procurement.

## First hour

```bash
vault serve                                    # note the tokens it prints
vault agent register --name "Sales Copilot" \
      --owner dana --tech-owner sam \
      --department sales --folder sales/       # keep the credential it prints
vault golden add "Maximum discount without Finance approval is 20%" \
      --folder sales/pricing/ --actor cfo --approver ceo
vault rules backtest "no payment authority above $50k"   # before enabling anything
vault doctor
```

Then point an agent at the MCP server (`npm run mcp`) or POST to `/api/ingest`.

## Data directory

```
data/
  signing-key.json     Ed25519 keypair, mode 0600 — back this up
  *.jsonl              one file per collection, append-only
  mirror/              continuous export to customer-owned storage
```

The signing key is generated **before** the first ledger entry is written. If you lose
it, past entries can no longer be signature-verified — the chain still verifies
structurally, but the strongest layer of the proof is gone. Back it up somewhere that
is not the same disk.

## Storage

Tiers: `HOT` (30 days, sub-50ms, full index) · `WARM` (to 12 months) · `COLD`
(1–3 years, metadata index only) · `ARCHIVE` (3+ years) · `WORM` (regulatory copy,
immutable for the retention period, never tiered down) · legal hold (any tier, but
promoted to WARM and frozen — retention cannot touch it).

Lifecycle rules are per data class, label, jurisdiction and folder, and **preview
before they run**: *"this schedule will move 41,200 conversations to Archive next month
— review."*

Bring Your Own Bucket targets: S3 (with Object Lock), Azure Blob (immutable policies),
GCS (Bucket Lock), R2, B2, Wasabi, MinIO, Ceph/Swift, NetApp/Dell/Pure, IBM COS, OCI,
or any S3-compatible endpoint.

## Keys

| Mode | Meaning |
|---|---|
| Vault-managed | simplest, default for self-serve |
| BYOK | customer generates and uploads; we use, can't export |
| CMK | customer's cloud KMS holds them (AWS KMS, Azure Key Vault, GCP KMS) |
| HYOK / External | keys never leave the customer's HSM; revoking cuts us off instantly |
| HSM | Thales, Entrust, CloudHSM, on-prem |
| Split-key / M-of-N | two named humans required to unlock a namespace |

Rotation re-wraps without re-encrypting the data. **Crypto-shredding** — destroying a
key to destroy the data — is the only honest way to prove erasure from immutable
backups, and it is what the erasure receipts cite for the backup line.

```bash
curl -X POST -H "Authorization: Bearer $ADMIN" \
     http://localhost:8080/api/admin/keys/sales/rotate
```

## Backup and DR

Point-in-time restore to the minute · continuous incremental plus daily full ·
cross-region replication with a "never leave this region" option · **RPO 5 minutes,
RTO 1 hour** · restore tested quarterly with results published to the customer ·
backups encrypted under the same key hierarchy so crypto-shredding reaches them ·
immutable backups with separate credentials for ransomware.

## The kill switch

```bash
vault killswitch status
vault killswitch engage 3 --reason "suspected poisoning in sales/"
vault killswitch engage 4 --folder sales/ --reason "contained"
vault killswitch release --reason "cleared"
vault killswitch test        # quarterly; the result goes in the ledger
```

Six graduated levels — see [SECURITY.md](SECURITY.md). Activation target is under 60
seconds for agents with transaction authority. In-flight writes are queued, not lost.
Auto-expiry forces re-authorisation so nobody forgets it's on. Reachable from mobile
and from an out-of-band channel, in case the main app is the problem.

## Monitoring

```bash
vault doctor      # ledger chain · fact integrity · three-way consistency · findings
vault status      # counts, uptime, module states
vault map         # agents, folders, shadow findings, coverage
vault hygiene --dry-run
```

`doctor` exits non-zero when something is genuinely wrong, so it drops straight into a
health check. It checks the ledger chain, fact-store integrity, and the three-way
consistency between ledger, facts and archive — then lists real findings (unowned
folders, Watch-mode agents, unpinned models, an unconfigured mirror) with the fix for
each.

Non-functional targets: write p50 <80ms / p95 <250ms / p99 <600ms · read p95 <150ms ·
search p95 <400ms · full-corpus chain verification under an hour · connector gap alert
within 15 minutes · erasure complete in 24h hot/warm, 7 days including backups and
archive · full-tenant export in under 24h at any size.

## Upgrades

Collections replay from their JSONL on load, so an upgrade is: stop, replace the code,
start. There is no migration step for additive fields. Anything else ships with a
one-shot script under `bin/`, and the ledger records that it ran.

## Troubleshooting

**"no credential has been issued for this agent"** — the agent is registered but has no
credential, or the credential expired. `vault agent credential <id>`. Credentials are
persisted, so this is never caused by a restart.

**Every write held with "routing uncertain … outside this agent's scope"** — folder
walls are keyed on department, not on the agent's folder list. Re-register with
`--department`, or open the wall. `vault agent register` warns about this at
registration time.

**`ledger verify` says TAMPERED with `signature_invalid`** — the data directory is
being read with a different signing key than the one that wrote it. Check that
`--data` points where you think, and that `signing-key.json` wasn't replaced.

**A rule won't compile** — the error lists every plain-language shape that does work,
or write it directly in the expression DSL: `claim matches /refund/ and amount > 5000`.
