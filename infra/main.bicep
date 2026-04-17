// AI Model Security Lab — Azure ML workspace with Defender for AI Services
// Deploys AML workspace + dependencies for demonstrating malicious model detection.
//
// The Defender plans themselves are configured at subscription scope (see deploy-lab.ps1)
// because Microsoft.Security/pricings is a subscription-level resource.

targetScope = 'resourceGroup'

@description('Deployment location. Defender for AI model security is available in commercial Azure regions.')
param location string = resourceGroup().location

@description('Short suffix appended to resource names for uniqueness.')
param suffix string = uniqueString(resourceGroup().id)

@description('Log Analytics workspace resource ID for Sentinel alert correlation.')
param sentinelWorkspaceId string

var workspaceName = 'aml-modelsec-${suffix}'
var storageName = 'amlmodelsec${suffix}'
var kvName = 'amlmodelsec-kv-${take(suffix, 8)}'
var appInsightsName = 'amlmodelsec-ai-${suffix}'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: sentinelWorkspaceId
  }
}

resource workspace 'Microsoft.MachineLearningServices/workspaces@2024-10-01' = {
  name: workspaceName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    friendlyName: 'AI Model Security Lab'
    description: 'AML workspace demonstrating Defender for AI Services model scanning.'
    storageAccount: storage.id
    keyVault: kv.id
    applicationInsights: appInsights.id
    publicNetworkAccess: 'Enabled'
  }
}

// Note: An AML registry (Microsoft.MachineLearningServices/registries) would
// let you share scanned-and-approved models across workspaces. It requires
// Microsoft.ContainerRegistry to be registered in the subscription and adds
// a Premium ACR to the cost footprint. Omitted here to keep the lab cheap;
// the Defender scanner runs against workspace-registered models just fine.

output workspaceName string = workspace.name
output workspaceId string = workspace.id
output storageName string = storage.name
output kvName string = kv.name
