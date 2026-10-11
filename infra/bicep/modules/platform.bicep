param name string
param location string
param privateNetworking bool = false
param isProd bool = false
param tags object

resource log 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${name}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    features: { disableLocalAuth: true }
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take('kv${replace(name, '-', '')}', 24)
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: isProd ? 90 : 7
    enablePurgeProtection: isProd ? true : null
    publicNetworkAccess: privateNetworking ? 'Disabled' : 'Enabled'
    networkAcls: {
      defaultAction: privateNetworking ? 'Deny' : 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: 'apim-${name}'
  location: location
  tags: tags
  sku: { name: 'Developer', capacity: 1 }
  identity: { type: 'SystemAssigned' }
  properties: {
    publisherEmail: 'platform@northglass.example'
    publisherName: 'Northglass Financial Services'
  }
}

resource api 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'northglass-loans'
  properties: {
    displayName: 'Northglass Loan API'
    path: 'loans'
    protocols: ['https']
    subscriptionRequired: false
  }
}

var policyXml = '''
<policies>
  <inbound>
    <base />
    <validate-azure-ad-token tenant-id="00000000-0000-0000-0000-00000000aaaa">
      <client-application-ids>
        <application-id>00000000-0000-0000-0000-00000000bbbb</application-id>
      </client-application-ids>
      <audiences>
        <audience>api://northglass-loan-api</audience>
      </audiences>
    </validate-azure-ad-token>
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
'''

resource apiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-09-01-preview' = {
  parent: api
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: policyXml
  }
}

// Key Vault Secrets User
var kvSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'

resource apimKv 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, apim.id, kvSecretsUser)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUser)
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output keyVaultName string = kv.name
output apimName string = apim.name
output logWorkspaceId string = log.id
