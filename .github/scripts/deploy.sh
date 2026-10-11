#!/usr/bin/env bash
# Deploy helpers. Never run from this repository so far: DEPLOY_ENABLED is not set.
set -euo pipefail
ENV_NAME="${TARGET_ENV:?TARGET_ENV is required}"
STACK="infra/terraform"
AZURE_TOOL="${AZURE_TOOL:-terraform}"

tf_init() {
  terraform -chdir="$STACK" init -input=false -backend-config="envs/${ENV_NAME}.backend.hcl" \
    -backend-config="resource_group_name=${TFSTATE_AZURE_RESOURCE_GROUP:?}" \
    -backend-config="storage_account_name=${TFSTATE_AZURE_STORAGE_ACCOUNT:?}" \
    -backend-config="container_name=tfstate"
}

provision() {
  if [[ "$AZURE_TOOL" == "bicep" ]]; then
    private=false
    [[ "$ENV_NAME" == "prod" ]] && private=true
    az deployment sub create --name "aauth-${ENV_NAME}-${GITHUB_RUN_ID:-local}" --location eastus2 \
      --template-file infra/bicep/main.bicep --parameters environment="$ENV_NAME" privateNetworking="$private" -o none
    return
  fi
  tf_init
  terraform -chdir="$STACK" apply -auto-approve -input=false -var-file="envs/${ENV_NAME}.tfvars"
}

smoke() {
  rg="rg-aauth-${ENV_NAME}-eus2-001"
  az keyvault show -g "$rg" --query "properties.enableRbacAuthorization" -o tsv | grep -q true
  az apim show -g "$rg" --query "name" -o tsv
  echo "smoke checks passed for ${ENV_NAME}"
}

destroy() {
  if [[ "$AZURE_TOOL" == "bicep" ]]; then
    az group delete --name "rg-aauth-${ENV_NAME}-eus2-001" --yes
    return
  fi
  tf_init
  terraform -chdir="$STACK" destroy -auto-approve -input=false -var-file="envs/${ENV_NAME}.tfvars"
}

cmd="${1:?usage: deploy.sh provision|smoke|destroy}"
"$cmd"
