mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "00000000-0000-0000-0000-000000000001"
      subscription_id = "00000000-0000-0000-0000-000000000002"
      object_id       = "00000000-0000-0000-0000-000000000003"
    }
  }
}

mock_provider "azuread" {}

override_resource {
  target          = azurerm_key_vault.this
  override_during = plan
  values = {
    id        = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
    vault_uri = "https://kv.vault.azure.net/"
  }
}

run "dev_defaults" {
  command = plan
  variables { environment = "dev" }
  assert {
    condition     = azurerm_resource_group.this.name == "rg-aauth-dev-eus2-001"
    error_message = "CAF naming"
  }
  assert {
    condition     = !azurerm_log_analytics_workspace.this.local_authentication_enabled
    error_message = "Log Analytics is Entra-only"
  }
  assert {
    condition     = azurerm_key_vault.this.rbac_authorization_enabled
    error_message = "Key Vault uses RBAC"
  }
  assert {
    condition     = azurerm_api_management.this.sku_name == "Developer_1"
    error_message = "APIM Developer SKU for validate-jwt"
  }
}

run "prod_private" {
  command = plan
  variables {
    environment        = "prod"
    private_networking = true
  }
  assert {
    condition     = !azurerm_key_vault.this.public_network_access_enabled
    error_message = "prod Key Vault has no public access"
  }
  assert {
    condition     = azurerm_key_vault.this.purge_protection_enabled
    error_message = "Key Vault has purge protection"
  }
}

run "rejects_unknown_environment" {
  command = plan
  variables { environment = "staging" }
  expect_failures = [var.environment]
}
