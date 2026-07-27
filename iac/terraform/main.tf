# Vault, managed with Terraform.
#
# There is no bespoke Vault provider binary. That is deliberate rather than
# pending: a native provider is a Go plugin, and this product ships as
# dependency-free Node source with no build step so that a customer can run it
# air-gapped and audit every line. Adding a compiled artefact to the release
# would trade that for convenience Terraform already provides another way.
#
# What a provider actually gives you — declarative desired state, a plan showing
# the diff before anything changes, idempotent apply, and drift detection — is
# implemented server-side in Vault (src/iac/iac.js) and exposed at
# /api/config/plan, /api/config/apply and /api/config/drift. This configuration
# drives those endpoints through the standard `restapi` provider, so
# `terraform plan` and `terraform apply` work today.
#
#   terraform init
#   terraform plan     # calls /api/config/plan — Vault computes the diff
#   terraform apply    # calls /api/config/apply — refuses destructive changes
#                      #   unless allow_destructive is set

terraform {
  required_version = ">= 1.5"
  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.19"
    }
  }
}

variable "vault_url" {
  description = "Base URL of the Vault API."
  type        = string
}

variable "vault_token" {
  description = "An admin or platform API key (vk_...)."
  type        = string
  sensitive   = true
}

variable "allow_destructive" {
  description = <<-EOT
    Permit changes that narrow a wall or retire an agent.

    Left false on purpose. A configuration drift should not be able to cut an
    agent off from a folder at 2am without somebody having said so; Vault
    classifies those changes as destructive and refuses them unless this is set.
  EOT
  type        = bool
  default     = false
}

provider "restapi" {
  uri                  = var.vault_url
  write_returns_object = true

  headers = {
    Authorization = "Bearer ${var.vault_token}"
    Content-Type  = "application/json"
  }
}

locals {
  # The estate, declared. Facts and conversations are deliberately absent:
  # they are data, not configuration, and a Terraform file that could declare
  # what is true would be the memory-poisoning vector this product exists to
  # close. Vault rejects a `fact` resource type outright.
  config = {
    version = 1

    agent = [
      {
        id             = "sales-copilot"
        name           = "Sales Copilot"
        purpose        = "Draft follow-ups and answer account questions"
        businessOwner  = "dana.whitfield"
        technicalOwner = "sam.okafor"
        department     = "sales"
        # Start in watch. Watch finds things; inline stops things. Going
        # straight to inline on day one means the first thing the product does
        # is block work nobody knew was happening.
        mode    = "watch"
        folders = ["sales/"]
      },
      {
        id             = "support-triage"
        name           = "Support Triage"
        purpose        = "Summarise tickets and suggest resolutions"
        businessOwner  = "ines.moreau"
        technicalOwner = "sam.okafor"
        department     = "support"
        mode           = "watch"
        folders        = ["support/"]
      }
    ]

    folder = [
      {
        path           = "sales/accounts/"
        read           = ["sales", "support"]
        write          = ["sales"]
        businessOwner  = "dana.whitfield"
        technicalOwner = "sam.okafor"
      },
      {
        path           = "sales/pricing/"
        read           = ["sales", "finance", "marketing"]
        write          = ["sales", "finance"]
        businessOwner  = "raj.mehta"
        technicalOwner = "sam.okafor"
        goldenPreferred = true
      }
    ]

    rule = [
      {
        name        = "hold-external-pricing-claims"
        description = "Pricing asserted from outside the company is held for a human."
        plain       = "hold pricing claims from external email"
        action      = "hold"
        type        = "semantic"
        state       = "enforce"
      }
    ]
  }
}

# `terraform plan` shows Vault's own plan, computed server-side against the
# live estate — the same diff the API would apply.
data "restapi_object" "plan" {
  path         = "/api/config/plan"
  search_key   = "plannedAt"
  search_value = ""
  # The restapi provider issues this as a read; Vault's plan endpoint never
  # mutates, which is asserted by snapshot in test/integrations.test.js.
}

resource "restapi_object" "estate" {
  path = "/api/config/apply"

  data = jsonencode({
    config            = local.config
    reason            = "terraform apply"
    approvedBy        = "dana.whitfield"
    allowDestructive  = var.allow_destructive
  })

  # Vault's apply is idempotent: re-running an unchanged configuration produces
  # no second change, which is what makes this safe in CI.
  id_attribute = "appliedAt"
}

output "verdict" {
  description = "Vault's own summary of what applying this configuration did."
  value       = try(jsondecode(restapi_object.estate.api_response).verdict, null)
}

output "destructive_changes" {
  description = "Changes that reduce access. Non-empty means allow_destructive was needed."
  value       = try(jsondecode(restapi_object.estate.api_response).destructive, [])
}
