# Azure mapping

| Portfolio piece | Azure service |
|---|---|
| Local OAuth / OIDC | Microsoft Entra ID (app registrations, app roles, CA) |
| JWKS / signing keys | Key Vault keys + rotation; APIM openid-config |
| `validate-jwt` | API Management inbound policy |
| Managed identity | DefaultAzureCredential on Container Apps / Functions |
| OBO | Entra on-behalf-of via MSAL |
| Agent identity | Entra agent application + federated credential |
| Audit → SOC | Log Analytics / Sentinel (companion repo) |
| IaC | Terraform (`azurerm` + `azuread`) and Bicep |

Nothing in this repository has been deployed.
