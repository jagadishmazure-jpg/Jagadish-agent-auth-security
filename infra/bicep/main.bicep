targetScope = 'subscription'

@allowed(['dev', 'prod'])
param environment string = 'dev'
param location string = 'eastus2'
param privateNetworking bool = false
param prefix string = 'aauth'

var name = '${prefix}-${environment}'
var rgName = 'rg-${name}-eus2-001'
var tags = {
  project: 'Jagadish-agent-auth-security'
  environment: environment
  company: 'northglass-fictional'
}

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: rgName
  location: location
  tags: tags
}

module platform 'modules/platform.bicep' = {
  name: 'platform'
  scope: rg
  params: {
    name: name
    location: location
    privateNetworking: privateNetworking
    isProd: environment == 'prod'
    tags: tags
  }
}

output resourceGroup string = rg.name
output keyVaultName string = platform.outputs.keyVaultName
output apimName string = platform.outputs.apimName
