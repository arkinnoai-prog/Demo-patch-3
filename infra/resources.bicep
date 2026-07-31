// Shared demo estate — resource-group-scoped.
//
// Provisions the cheapest viable infra for the Ba0Ba0 demo repos: one Log Analytics
// workspace, one Container Apps environment, one Burstable Postgres, and a Container App
// per demo (each with its own database). Everything is sized for "showcase, few users".
//
// Called by main.bicep, which creates the resource group first.

@description('Azure region. Southeast Asia is physically in Singapore.')
param location string

@description('Short prefix for shared resource names, e.g. "baobao".')
param namePrefix string

@description('PostgreSQL administrator login.')
param pgAdminUser string

@description('PostgreSQL administrator password.')
@secure()
param pgAdminPassword string

@description('Demo apps to host. Each gets its own Postgres database and Container App.')
param apps array

@description('Image every app starts on. The per-repo deploy workflow replaces it on the first tag.')
param containerImage string

@description('Minimum replicas. 0 = scale-to-zero (cheapest, cold start on first hit); 1 = always warm.')
param minReplicas int = 0

// --- observability ----------------------------------------------------------

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${namePrefix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// --- Container Apps environment (shared by every demo) ----------------------

resource caEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${namePrefix}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// --- shared PostgreSQL Flexible Server (cheapest Burstable tier) -------------

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: 'psql-${namePrefix}'
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: pgAdminUser
    administratorLoginPassword: pgAdminPassword
    storage: { storageSizeGB: 32 }
    backup: { backupRetentionDays: 7, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
    authConfig: { activeDirectoryAuth: 'Disabled', passwordAuth: 'Enabled' }
  }
}

// Let Container Apps (and other Azure services) reach the server. The 0.0.0.0 rule is
// Azure's "allow access from Azure services" special case — minimal, demo-appropriate.
resource pgFirewallAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = {
  parent: postgres
  name: 'AllowAllAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

// One database per demo app.
resource databases 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-06-01-preview' = [
  for app in apps: {
    parent: postgres
    name: app.db
    properties: { charset: 'UTF8', collation: 'en_US.utf8' }
  }
]

// --- one Container App per demo ---------------------------------------------

resource containerApps 'Microsoft.App/containerApps@2024-03-01' = [
  for app in apps: {
    name: app.name
    location: location
    properties: {
      managedEnvironmentId: caEnv.id
      configuration: {
        ingress: {
          external: true
          targetPort: 8080
          transport: 'auto'
          traffic: [ { latestRevision: true, weight: 100 } ]
        }
        // The full SQLAlchemy URL (Postgres-only app default). SSL is required by the
        // Flexible Server. Stored as a Container App secret, referenced by env below.
        secrets: [
          {
            name: 'database-url'
            value: 'postgresql+psycopg2://${pgAdminUser}:${pgAdminPassword}@${postgres.properties.fullyQualifiedDomainName}:5432/${app.db}?sslmode=require'
          }
        ]
      }
      template: {
        containers: [
          {
            name: app.name
            image: containerImage
            resources: { cpu: json('0.25'), memory: '0.5Gi' }
            env: [
              { name: 'APP_ENV', value: 'production' }
              { name: 'IMAGE_TAG', value: 'bootstrap' }
              { name: 'DATABASE_URL', secretRef: 'database-url' }
            ]
          }
        ]
        scale: { minReplicas: minReplicas, maxReplicas: 2 }
      }
    }
    dependsOn: [ databases ]
  }
]

output appFqdns array = [for (app, i) in apps: containerApps[i].properties.configuration.ingress.fqdn]
output postgresHost string = postgres.properties.fullyQualifiedDomainName
