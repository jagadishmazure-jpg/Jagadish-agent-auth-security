# Deployment

**Nothing is deployed.** `DEPLOY_ENABLED` is not set, so `deploy.yml` and `teardown.yml` only report the gate.

To deploy (not recommended for a practice subscription without a budget lock):

1. Configure GitHub OIDC to Azure (federated credential; no client secret)
2. Create Environments `dev` and `prod` with required reviewers on `prod`
3. Set `DEPLOY_ENABLED=true` and the `AZURE_*` / `TFSTATE_*` variables
4. Run the deploy workflow

Prefer tearing down the same day. This portfolio exists to show IaC quality, not a live bill.
