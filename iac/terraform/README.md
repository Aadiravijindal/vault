# Managing Vault with Terraform

## Why there is no `vault` provider binary here

A native Terraform provider is a compiled Go plugin. This product ships as
dependency-free Node source with no build step, specifically so a customer can
read every line, run it air-gapped, and stand it up from an export without our
help. Publishing a compiled binary alongside it would undercut that for
convenience Terraform can already deliver another way.

The four things a provider gives you all exist server-side:

| Provider capability | Where it lives |
|---|---|
| Declarative desired state | `POST /api/config/apply` |
| Plan before change | `POST /api/config/plan` — computed against the live estate, never mutates |
| Idempotent apply | Re-applying an unchanged configuration produces no change |
| Drift detection | `POST /api/config/drift` |

`main.tf` drives them through Mastercard's `restapi` provider.

## Usage

```bash
terraform init
terraform plan  -var="vault_url=https://vault.internal" -var="vault_token=$VAULT_TOKEN"
terraform apply -var="vault_url=https://vault.internal" -var="vault_token=$VAULT_TOKEN"
```

Without Terraform at all:

```bash
node bin/vault.js config plan  --file estate.json
node bin/vault.js config apply --file estate.json --actor ops
node bin/vault.js config drift --file estate.json
```

## Adopting an existing installation

Do not hand-write the first configuration. Export what is already there:

```bash
curl -H "Authorization: Bearer $VAULT_TOKEN" https://vault.internal/api/config/export > estate.json
```

Planning that export against the same instance produces zero changes — asserted
by a test — so adoption is a no-op rather than a rewrite.

## Destructive changes

`allow_destructive` defaults to false. Vault classifies a change as destructive
when it narrows a folder's read or write list, removes a folder from an agent's
scope, retires an agent, or disconnects a connector, and refuses the apply
unless the flag is set. The plan names each one and why it matters.

This is not caution for its own sake: a drift correction that quietly removes
`support` from a read list at 2am is how a working agent stops working and
nobody knows why for a day.

## What cannot be managed here

Facts, conversations, golden facts and review decisions. They are data and
judgments, not configuration. Vault rejects an unknown resource type with the
list of ones it accepts — a configuration file that could declare what is true
would be the memory-poisoning vector the whole product exists to close.

Credentials are also not stored in configuration. Pass them at apply time
(`credentials` in the request body), where they go into the connector's
in-memory secret store and never into the collection, the ledger or a log.
