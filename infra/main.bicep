// Ba0Ba0 demo estate — one command stands up the whole resource group.
//
//   az deployment sub create \
//     --location southeastasia \
//     --template-file infra/main.bicep \
//     --parameters infra/main.bicepparam
//
// Creates the resource group in Singapore (Southeast Asia) and everything inside it:
// Log Analytics, a shared Container Apps environment, a Burstable Postgres, and a
// Container App per demo. Re-running is an idempotent update. See DEPLOYMENT.md.

targetScope = 'subscription'

@description('Region for the resource group and all resources. Southeast Asia = Singapore.')
param location string = 'southeastasia'

@description('Resource group to create/use.')
param resourceGroupName string = 'rg-baobao-demos-sea'

@description('Short prefix for shared resource names.')
param namePrefix string = 'baobao'

@description('PostgreSQL administrator login.')
param pgAdminUser string = 'baobaoadmin'

@description('PostgreSQL administrator password (supply at deploy time — never commit it).')
@secure()
param pgAdminPassword string

@description('Demo apps to host. Each entry = { name: <container-app name>, db: <database name> }.')
param apps array = [
  { name: 'demo-patch-3', db: 'baobao' }
]

@description('Bootstrap image for first provision; the deploy workflow swaps in the real GHCR image.')
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

@description('Minimum replicas per app. 0 = scale-to-zero (cheapest).')
param minReplicas int = 0

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

module estate 'resources.bicep' = {
  scope: rg
  name: 'estate'
  params: {
    location: location
    namePrefix: namePrefix
    pgAdminUser: pgAdminUser
    pgAdminPassword: pgAdminPassword
    apps: apps
    containerImage: containerImage
    minReplicas: minReplicas
  }
}

@description('Public HTTPS hostnames of each demo app, in the same order as the apps parameter.')
output appFqdns array = estate.outputs.appFqdns

@description('PostgreSQL host (shared by all demos).')
output postgresHost string = estate.outputs.postgresHost
