# Terraform (Azure)

| File | What it does |
|---|---|
| `versions.tf` | Required providers |
| `providers.tf` | azurerm + azuread |
| `backend.tf` | AzureRM backend with Entra auth |
| `variables.tf` | Inputs |
| `locals.tf` | Naming and tags |
| `main.tf` | RG, Log Analytics, Key Vault, APIM, Entra apps |
| `outputs.tf` | Outputs |
| `.tflint.hcl` | Lint config |
| `envs/` | dev/prod tfvars and backend |
| `tests/` | Offline plan tests |
| `.terraform.lock.hcl` | Provider lock file |
