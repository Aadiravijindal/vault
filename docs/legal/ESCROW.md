# Source-code escrow

## The usual arrangement, and why it is weaker than it looks

Software escrow typically means: the vendor deposits source with a third-party
agent, and on a release condition — insolvency, breach, abandonment — the
customer receives it.

Three things usually go wrong.

1. **The deposit is stale.** Deposits are often annual. The release happens
   against a version nobody has run in production for months.
2. **The deposit is incomplete.** Source without the build toolchain, the private
   dependencies, the CI configuration and the deployment scripts is a puzzle, not
   a product. Verification services exist precisely because incomplete deposits
   are the norm.
3. **The release condition is litigated.** Insolvency proceedings are the least
   convenient moment to argue with an escrow agent about whether a condition has
   been met.

## What this product does instead

The escrow model exists to solve "the customer cannot run the software without
the vendor." Vault addresses that condition directly rather than contractually:

| Escrow tries to guarantee | Vault's position |
|---|---|
| You get the source | Licensed customers already have it. It ships as readable source. |
| The source builds | There is no build step. The source *is* the artefact. |
| You have the dependencies | There are none. `node:` builtins only. |
| It runs without the vendor | No licence server, no phone-home, no network requirement. Runs air-gapped. |
| You can read your data | The export is newline-delimited JSON with a documented schema. |
| You can trust the data | The verifier is Apache-2.0 and imports nothing from the product. |

A customer with today's release, today's export and their own signing key is
already in the position an escrow release is supposed to deliver — without a
release condition, an agent, or a dispute.

## When escrow is still worth doing

Some procurement processes require an escrow agreement regardless, and some
security teams reasonably want a copy held outside both parties. That is a fair
ask, and the practical version is:

- **Deposit on every release**, not annually. There is no build to reproduce, so
  the deposit is a tarball of the repository at a tagged commit.
- **Deposit the provenance too.** `node bin/vault-supplychain.js --sbom --attest`
  produces a CycloneDX SBOM with a file-level SHA-256 inventory and an in-toto
  statement. That is what lets the agent verify the deposit matches the release,
  rather than verifying that a file exists.
- **Include the verifier separately.** It is Apache-2.0; it can simply be
  published, which is stronger than escrowing it.
- **Test the release, once.** Have the agent perform a restore from a deposit and
  a customer export into a clean environment. `vault.drill.run()` is that test,
  and it produces a signed record of the result.

## What escrow cannot give you

It cannot give you your signing key, because we do not have it. It cannot give
you your data, because in the intended deployment we do not hold that either —
your export and your mirror do. And it cannot make an incomplete deposit
complete. The reason the answers above are short is that the architecture removed
the problems rather than insuring against them.

## Terms

Escrow agreements are commercial instruments and their terms — agent, release
conditions, deposit cadence, verification level, cost allocation — belong in the
signed agreement, drafted with counsel. Nothing in this document is a contractual
commitment; it describes what the product makes possible so that the commitment
can be a small one.
