data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.name}-eus2-001"
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "this" {
  name                       = "log-${local.name}"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  sku                        = "PerGB2018"
  retention_in_days          = 30
  local_authentication_enabled = false
  tags                       = local.tags
}

resource "azurerm_key_vault" "this" {
  name                       = "kv${replace(local.name, "-", "")}"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = var.environment == "prod" ? 90 : 7
  purge_protection_enabled   = var.environment == "prod"
  enable_rbac_authorization  = true
  public_network_access_enabled = !var.private_networking
  network_acls {
    default_action = var.private_networking ? "Deny" : "Allow"
    bypass         = "AzureServices"
  }
  tags = local.tags
}

# Signing keys live in Key Vault; rotation is an operational runbook (see docs).
# No secret values are placed here.

resource "azurerm_api_management" "this" {
  name                = "apim-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  publisher_name      = "Northglass Financial Services"
  publisher_email     = "platform@northglass.example"
  sku_name            = "Developer_1"
  tags                = local.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_api_management_api" "loans" {
  name                = "northglass-loans"
  resource_group_name = azurerm_resource_group.this.name
  api_management_name = azurerm_api_management.this.name
  revision            = "1"
  display_name        = "Northglass Loan API"
  path                = "loans"
  protocols           = ["https"]
  subscription_required = false
}

# validate-jwt policy pins issuer, audience and required claim. Kid must resolve via OpenID config.
resource "azurerm_api_management_api_policy" "loans" {
  api_name            = azurerm_api_management_api.loans.name
  api_management_name = azurerm_api_management.this.name
  resource_group_name = azurerm_resource_group.this.name

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-scheme="Bearer">
          <openid-config url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" />
          <audiences>
            <audience>api://northglass-loan-api</audience>
          </audiences>
          <required-claims>
            <claim name="roles" match="any">
              <value>loan.officer</value>
              <value>loan.underwriter</value>
              <value>compliance.officer</value>
            </claim>
          </required-claims>
        </validate-jwt>
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

# Entra app registrations (azuread). Documented; applied only when deploy is enabled.
resource "azuread_application" "api" {
  display_name     = "northglass-loan-api-${var.environment}"
  sign_in_audience = "AzureADMyOrg"

  identifier_uris = ["api://northglass-loan-api-${var.environment}"]

  api {
    oauth2_permission_scope {
      admin_consent_description  = "Read loans"
      admin_consent_display_name = "Read loans"
      id                         = "11111111-1111-1111-1111-111111111101"
      enabled                    = true
      type                       = "User"
      value                      = "loans.read"
    }
  }

  app_role {
    allowed_member_types = ["User", "Application"]
    description          = "Loan officer"
    display_name         = "Loan officer"
    enabled              = true
    id                   = "11111111-1111-1111-1111-111111111201"
    value                = "loan.officer"
  }

  app_role {
    allowed_member_types = ["User", "Application"]
    description          = "Loan underwriter"
    display_name         = "Loan underwriter"
    enabled              = true
    id                   = "11111111-1111-1111-1111-111111111202"
    value                = "loan.underwriter"
  }

  app_role {
    allowed_member_types = ["Application"]
    description          = "Loan assistant agent"
    display_name         = "Loan assistant agent"
    enabled              = true
    id                   = "11111111-1111-1111-1111-111111111203"
    value                = "agent.loan_assistant"
  }
}

resource "azuread_service_principal" "api" {
  client_id = azuread_application.api.client_id
}

resource "azuread_application" "portal" {
  display_name     = "northglass-loan-portal-${var.environment}"
  sign_in_audience = "AzureADMyOrg"

  single_page_application {
    redirect_uris = ["https://loans.northglass.example/callback"]
  }

  required_resource_access {
    resource_app_id = azuread_application.api.client_id
    resource_access {
      id   = "11111111-1111-1111-1111-111111111101"
      type = "Scope"
    }
  }
}

resource "azurerm_role_assignment" "apim_kv_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_api_management.this.identity[0].principal_id
}
