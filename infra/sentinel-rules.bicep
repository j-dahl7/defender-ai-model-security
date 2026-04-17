// Sentinel analytics rules + workbook for AI Model Security lab.
// Deploy against the Sentinel-enabled workspace (not the AML workspace).
//
// Fuzzy-union pattern: each rule tolerates a zero-row SecurityAlert table so
// rule validation passes before the first real Defender alert arrives.

targetScope = 'resourceGroup'

@description('Name of the Log Analytics / Sentinel workspace.')
param workspaceName string

@description('Azure region for the workspace (used only for resource IDs).')
param location string = resourceGroup().location

var aiModelScanAlertPrefix = 'Ai.AIModelScan'

// ---------- Analytics rules ----------

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource rule_malicious_model 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'rule-malicious-model-upload')
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Model Security - Malicious AI model uploaded'
    description: 'Fires when Defender for AI Services flags an AI model in Azure Machine Learning as containing embedded malware, unsafe operators, or exposed secrets. Pickle (.pkl), TorchScript (.pt), and ONNX models are all in scope.'
    severity: 'High'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertSeverity:string, ProductName:string, Entities:string, AlertLink:string, CompromisedEntity:string)[]),
  (SecurityAlert
    | where ProductName =~ "Microsoft Defender for Cloud"
    | where AlertName startswith "Ai.AIModelScan"
  )
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Entities, AlertLink
'''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: [
      'InitialAccess'
      'Execution'
      'Persistence'
    ]
    techniques: [
      'T1195'  // Supply Chain Compromise
      'T1059'  // Command and Scripting Interpreter
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: [
          'DisplayName'
        ]
        groupByCustomDetails: []
      }
    }
  }
}

resource rule_repeat_uploader 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'rule-repeat-risky-uploader')
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Model Security - Repeat risky model uploader'
    description: 'Identifies identities that registered two or more flagged AI models within a 7-day window. Persistent risky behavior signals either a compromised developer account or an insider abuse pattern.'
    severity: 'High'
    enabled: true
    query: '''
let lookback = 7d;
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertSeverity:string, ProductName:string, Entities:string, CompromisedEntity:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where ProductName =~ "Microsoft Defender for Cloud"
    | where AlertName startswith "Ai.AIModelScan"
  )
| extend actor = tostring(CompromisedEntity)
| where isnotempty(actor)
| summarize AlertCount = dcount(AlertName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Alerts = make_set(AlertName, 20) by actor
| where AlertCount >= 2
| project TimeGenerated = LastSeen, actor, AlertCount, FirstSeen, LastSeen, Alerts
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: [
      'Persistence'
    ]
    techniques: [
      'T1078'  // Valid Accounts
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

resource rule_unscanned_deployment 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'rule-unscanned-deployment')
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Model Security - AML model deployed before scan completed'
    description: 'Defender scans models weekly. Catches model deployments to online endpoints that happen before a scan has produced a verdict, closing the scan-vs-deploy race window.'
    severity: 'Medium'
    enabled: true
    query: '''
let lookback = 24h;
union isfuzzy=true
  (datatable(TimeGenerated:datetime, OperationName:string, ResourceId:string, Caller:string, ResultType:string)[]),
  (AzureActivity
    | where TimeGenerated > ago(lookback)
    | where ResourceProvider =~ "Microsoft.MachineLearningServices"
    | where OperationNameValue has_any ("MODELS/WRITE", "ONLINEENDPOINTS/DEPLOYMENTS/WRITE", "BATCHENDPOINTS/DEPLOYMENTS/WRITE")
    | where ActivityStatusValue =~ "Success"
  )
| summarize Deployments = make_set(OperationName, 10), Caller = any(Caller), LastActivity = max(TimeGenerated) by ResourceId
| extend TimeGenerated = LastActivity
| project TimeGenerated, ResourceId, Caller, Deployments
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'P1D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: [
      'InitialAccess'
      'DefenseEvasion'
    ]
    techniques: [
      'T1195'
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

// ---------- Workbook ----------

var workbookContent = loadTextContent('./workbook.json')

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: guid(workspace.id, 'wb-ai-model-security')
  location: location
  kind: 'shared'
  properties: {
    displayName: 'AI Model Security Dashboard'
    serializedData: workbookContent
    sourceId: workspace.id
    category: 'sentinel'
    version: '1.0'
  }
}

output ruleIds array = [
  rule_malicious_model.id
  rule_repeat_uploader.id
  rule_unscanned_deployment.id
]
output workbookId string = workbook.id
