// Parameters for main.bicep.
//
// The Postgres password is read from an environment variable so it is never committed.
// Set it before deploying:
//
//   export PG_ADMIN_PASSWORD='<a strong password>'      # bash
//   $env:PG_ADMIN_PASSWORD = '<a strong password>'      # PowerShell
//
// Then:
//   az deployment sub create --location southeastasia \
//     --template-file infra/main.bicep --parameters infra/main.bicepparam

using './main.bicep'

param location = 'southeastasia'
param resourceGroupName = 'rg-baobao-demos-sea'
param namePrefix = 'baobao'
param pgAdminUser = 'baobaoadmin'
param pgAdminPassword = readEnvironmentVariable('PG_ADMIN_PASSWORD')

// All three demos share this resource group, environment, and Postgres server.
// Uncomment the other two once their repos exist; each gets its own database and app.
param apps = [
  { name: 'demo-patch-3', db: 'baobao' }
  // { name: 'demo-patch-1', db: 'paymentsdb' }
  // { name: 'demo-patch-2', db: 'portaldb' }
]

// Scale-to-zero keeps idle cost near nothing. Set to 1 to keep every app always warm.
param minReplicas = 0
