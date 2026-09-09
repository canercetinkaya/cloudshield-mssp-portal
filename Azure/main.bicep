// ==============================================================================
// KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)
// Infrastructure as Code: Azure Container Apps Serverless Architecture
// Optimized for Azure MCT Subscription (<$10/mo) and Enterprise Production
// ==============================================================================

@description('Kaynakların konuşlandırılacağı Azure bölgesi')
param location string = resourceGroup().location

@description('Kaynak adı öneki (Örn: cloudshield-mssp)')
@minLength(3)
@maxLength(16)
param prefix string = 'cloudshield-mssp'

@description('Konuşlandırma ortamı')
@allowed([
  'poc'
  'dev'
  'prod'
])
param environmentType string = 'poc'

@description('MSSP Portal Konteyner İmajı')
param containerImage string = 'mcr.microsoft.com/powershell:7.4-ubuntu-22.04'

@description('Konteyner vCPU miktarı (0.25, 0.5, 0.75, 1.0)')
param cpuCores string = '0.5'

@description('Konteyner RAM miktarı (0.5Gi, 1.0Gi, 2.0Gi)')
param memorySize string = '1.0Gi'

@description('Opsiyonel: Key Vault üzerinde sır ve sertifika yönetimi yapacak yönetici/kullanıcı Object ID (GUID)')
param adminPrincipalId string = ''

@description('Yönetici kimlik türü (User, ServicePrincipal, Group)')
@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
param adminPrincipalType string = 'User'

var uniqueSuffix = substring(uniqueString(resourceGroup().id), 0, 6)
var storageAccountName = toLower('${replace(prefix, '-', '')}${uniqueSuffix}sa')
var keyVaultName = toLower('cs-kv-${uniqueSuffix}')
var logAnalyticsName = '${prefix}-${environmentType}-law'
var acaEnvName = '${prefix}-${environmentType}-env'
var containerAppName = '${prefix}-${environmentType}-app'

// 1. Log Analytics Workspace (Aylık 5GB Ücretsiz Katman)
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// 2. Azure Storage Account (Rapor Arşivi ve Kalıcı Veriler İçin)
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
}

resource reportsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'reports-archive'
  properties: {
    publicAccess: 'None'
  }
}

resource dataContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'portal-data'
  properties: {
    publicAccess: 'None'
  }
}

// 3. Azure Key Vault (Müşteri Secret ve Sertifikaları İçin)
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    tenantId: subscription().tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

// 4. Azure Container Apps Environment
resource acaEnvironment 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: acaEnvName
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

// 5. Azure Container App (MCT Bütçe Dostu Sunucusuz Çalışma & Sıfıra Ölçeklenme)
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: containerAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: acaEnvironment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'cloudshield-mssp-portal'
          image: containerImage
          resources: {
            cpu: json(cpuCores)
            memory: memorySize
          }
          env: [
            {
              name: 'PORT'
              value: '8080'
            }
            {
              name: 'AZURE_STORAGE_ACCOUNT'
              value: storageAccount.name
            }
            {
              name: 'AZURE_KEYVAULT_URL'
              value: keyVault.properties.vaultUri
            }
            {
              name: 'ENVIRONMENT'
              value: environmentType
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0 // Boşta beklerken $0 maliyet için sıfıra iner
        maxReplicas: 3
        rules: [
          {
            name: 'http-rule'
            http: {
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
}

// ==============================================================================
// Azure RBAC Rol Atamaları (Sıfır Güven & Şifresiz Bulut Mimarisi)
// ==============================================================================

// 1. Storage Blob Data Contributor Rolü (Container App Managed Identity -> Storage Account)
resource blobDataContributorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' // Storage Blob Data Contributor
}

resource roleAssignmentStorage 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, containerApp.id, blobDataContributorRole.id)
  scope: storageAccount
  properties: {
    roleDefinitionId: blobDataContributorRole.id
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// 2. Key Vault Secrets User Rolü (Container App Managed Identity -> Key Vault)
// Client Secret anahtarlarını bellek içinde okumak için en az yetki (least-privilege) sağlar.
resource keyVaultSecretsUserRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
}

resource roleAssignmentKeyVaultSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, containerApp.id, keyVaultSecretsUserRole.id)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole.id
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// 3. Key Vault Certificate User Rolü (Container App Managed Identity -> Key Vault)
// CBA (Certificate-Based Authentication) için sertifika verilerini okuma yetkisi sağlar.
resource keyVaultCertificateUserRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: 'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba' // Key Vault Certificate User
}

resource roleAssignmentKeyVaultCerts 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, containerApp.id, keyVaultCertificateUserRole.id)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultCertificateUserRole.id
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// 4. Key Vault Administrator Rolü (Opsiyonel: Yönetici / Dağıtım Yapan Mühendis İçin)
// Key Vault RBAC modunda abonelik Contributor'ları varsayılan olarak secret okuyup yazamaz.
// Dağıtım yapan yöneticinin müşteri secret/sertifikalarını yükleyebilmesi için bu rol atanır.
resource keyVaultAdminRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: '00482a5a-887f-4fb3-b391-77e1613c4fc0' // Key Vault Administrator
}

resource roleAssignmentKeyVaultAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(adminPrincipalId)) {
  name: guid(keyVault.id, adminPrincipalId, keyVaultAdminRole.id)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultAdminRole.id
    principalId: adminPrincipalId
    principalType: adminPrincipalType
  }
}

// ==============================================================================
// Dağıtım Çıktıları
// ==============================================================================
output portalFqdn string = containerApp.properties.configuration.ingress.fqdn
output portalUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output storageAccountName string = storageAccount.name
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output containerAppName string = containerApp.name
output containerAppPrincipalId string = containerApp.identity.principalId
output logAnalyticsWorkspaceId string = logAnalytics.properties.customerId
