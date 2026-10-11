# Remote state in Azure Storage with Entra ID auth (no access keys).
terraform {
  backend "azurerm" {
    use_azuread_auth = true
  }
}
