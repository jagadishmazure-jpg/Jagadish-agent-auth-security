output "resource_group" { value = azurerm_resource_group.this.name }
output "key_vault_uri" { value = azurerm_key_vault.this.vault_uri }
output "apim_name" { value = azurerm_api_management.this.name }
output "api_app_client_id" { value = azuread_application.api.client_id }
output "portal_app_client_id" { value = azuread_application.portal.client_id }
