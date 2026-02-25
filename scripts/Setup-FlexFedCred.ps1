#Requires -Version 7.4
#Requires -Modules Az, GitHub

<#
    .SYNOPSIS
    Sets up an Azure User-Assigned Managed Identity with a flexible federated credential for GitHub Actions.

    .DESCRIPTION
    This script performs the following end-to-end setup:
    1. Creates a new Azure Resource Group.
    2. Creates a User-Assigned Managed Identity (UAMI) in the resource group.
    3. Configures a flexible federated identity credential on the UAMI that trusts all
       GitHub Actions runs from any repository in the specified GitHub organization.
    4. Uses the GitHub PowerShell module to store the AZURE_CLIENT_ID, AZURE_TENANT_ID,
       and AZURE_SUBSCRIPTION_ID as organization-level secrets on the specified GitHub organization.

    .EXAMPLE
    ```powershell
    ./scripts/Setup-FlexFedCred.ps1
    ```

    Runs the full setup with default values.

    .EXAMPLE
    ```powershell
    ./scripts/Setup-FlexFedCred.ps1 -ResourceGroupName 'rg-custom' -Location 'westeurope'
    ```

    Runs the setup with a custom resource group name and location.

    .NOTES
    Prerequisites:
    - Az PowerShell module installed and authenticated (`Connect-AzAccount`).
    - The GitHub PowerShell module installed (`Install-Module -Name GitHub`).
    - Authenticated to GitHub with permissions to manage organization secrets (`Connect-GitHub`).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword', '',
    Justification = 'FederatedCredentialName is a resource name, not a secret.'
)]
[CmdletBinding()]
param(
    # The name of the resource group to create.
    [Parameter()]
    [string] $ResourceGroupName = 'rg-msxorg-github',

    # The Azure region for the resource group and managed identity.
    [Parameter()]
    [string] $Location = 'swedencentral',

    # The name of the user-assigned managed identity.
    [Parameter()]
    [string] $ManagedIdentityName = 'mi-msxorg-github',

    # The name of the federated identity credential.
    [Parameter()]
    [string] $FederatedCredentialName = 'github-msxorg-all-repos',

    # The GitHub organization name.
    [Parameter()]
    [string] $GitHubOrganization = 'MSXOrg'
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

#region Validate prerequisites
Write-Information '--- Validating prerequisites ---'

# Verify Azure PowerShell is authenticated
$azContext = Get-AzContext
if (-not $azContext) {
    throw 'Azure PowerShell is not authenticated. Run "Connect-AzAccount" first.'
}
$subscriptionId = $azContext.Subscription.Id
$tenantId = $azContext.Tenant.Id
Write-Information "  Subscription: $($azContext.Subscription.Name) ($subscriptionId)"
Write-Information "  Tenant:       $tenantId"

# Verify GitHub authentication
$ghContext = Get-GitHubContext
if (-not $ghContext) {
    throw 'Not authenticated to GitHub. Run "Connect-GitHub" first.'
}
Write-Information "  GitHub context: $($ghContext.Name)"
#endregion

#region Step 1 - Create Resource Group
Write-Information ''
Write-Information '--- Step 1: Create Resource Group ---'

$existingRg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if ($existingRg) {
    Write-Information "  Resource group '$ResourceGroupName' already exists, skipping creation."
} else {
    Write-Information "  Creating resource group '$ResourceGroupName' in '$Location'..."
    $null = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    Write-Information "  Resource group '$ResourceGroupName' created."
}
#endregion

#region Step 2 - Create User-Assigned Managed Identity
Write-Information ''
Write-Information '--- Step 2: Create User-Assigned Managed Identity ---'

$mi = Get-AzUserAssignedIdentity -Name $ManagedIdentityName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ($mi) {
    Write-Information "  Managed identity '$ManagedIdentityName' already exists, skipping creation."
} else {
    Write-Information "  Creating managed identity '$ManagedIdentityName'..."
    $miParams = @{
        Name              = $ManagedIdentityName
        ResourceGroupName = $ResourceGroupName
        Location          = $Location
    }
    $mi = New-AzUserAssignedIdentity @miParams
    Write-Information "  Managed identity '$ManagedIdentityName' created."
}

$clientId = $mi.ClientId
$principalId = $mi.PrincipalId
$miResourceId = $mi.Id
Write-Information "  Client ID:    $clientId"
Write-Information "  Principal ID: $principalId"
#endregion

#region Step 3 - Create Flexible Federated Identity Credential
Write-Information ''
Write-Information '--- Step 3: Create Flexible Federated Identity Credential ---'

# New-AzFederatedIdentityCredential does not support flexible FICs (claimsMatchingExpression).
# We must use Invoke-AzRestMethod with the preview ARM API.
$ficPath = "$miResourceId/federatedIdentityCredentials/$($FederatedCredentialName)?api-version=2025-01-31-preview"

$ficBody = @{
    properties = @{
        issuer                   = 'https://token.actions.githubusercontent.com'
        audiences                = @('api://AzureADTokenExchange')
        claimsMatchingExpression = @{
            value           = "claims['sub'] matches 'repo:$GitHubOrganization/*'"
            languageVersion = 1
        }
    }
} | ConvertTo-Json -Depth 5 -Compress

Write-Information "  Expression: claims['sub'] matches 'repo:$GitHubOrganization/*'"
Write-Information "  Creating flexible federated credential '$FederatedCredentialName'..."

$ficRestParams = @{
    Path    = $ficPath
    Method  = 'PUT'
    Payload = $ficBody
}
$ficResponse = Invoke-AzRestMethod @ficRestParams

if ($ficResponse.StatusCode -notin 200, 201) {
    throw "Failed to create flexible federated identity credential: $($ficResponse.Content)"
}

$fic = $ficResponse.Content | ConvertFrom-Json
Write-Information "  Federated credential '$($fic.name)' created successfully."
Write-Information "  Issuer:     $($fic.properties.issuer)"
Write-Information "  Expression: $($fic.properties.claimsMatchingExpression.value)"
#endregion

#region Step 4 - Store secrets on GitHub organization
Write-Information ''
Write-Information '--- Step 4: Store secrets on GitHub organization ---'

$secrets = @{
    AZURE_CLIENT_ID       = $clientId
    AZURE_TENANT_ID       = $tenantId
    AZURE_SUBSCRIPTION_ID = $subscriptionId
}

foreach ($entry in $secrets.GetEnumerator()) {
    Write-Information "  Setting secret '$($entry.Key)' on organization '$GitHubOrganization'..."
    $secretParams = @{
        Owner      = $GitHubOrganization
        Name       = $entry.Key
        Value      = $entry.Value
        Visibility = 'All'
    }
    Set-GitHubSecret @secretParams
}

Write-Information '  Organization secrets configured.'
#endregion

#region Summary
Write-Information ''
Write-Information '=== Setup Complete ==='

# Fetch the final state of the managed identity
Write-Information ''
Write-Information '--- Managed Identity ---'
$finalMi = Get-AzUserAssignedIdentity -Name $ManagedIdentityName -ResourceGroupName $ResourceGroupName
$finalMi | Format-List Name, ResourceGroupName, Location, ClientId, PrincipalId, TenantId, Id | Out-String | ForEach-Object { Write-Information $_.TrimEnd() }

# Fetch the final state of the flexible federated identity credential
Write-Information '--- Flexible Federated Identity Credential ---'
$ficGetPath = "$($finalMi.Id)/federatedIdentityCredentials/$($FederatedCredentialName)?api-version=2025-01-31-preview"
$ficGetResponse = Invoke-AzRestMethod -Path $ficGetPath -Method GET
if ($ficGetResponse.StatusCode -eq 200) {
    $finalFic = $ficGetResponse.Content | ConvertFrom-Json
    [PSCustomObject]@{
        Name       = $finalFic.name
        Issuer     = $finalFic.properties.issuer
        Audiences  = $finalFic.properties.audiences -join ', '
        Expression = $finalFic.properties.claimsMatchingExpression.value
        Language   = $finalFic.properties.claimsMatchingExpression.languageVersion
    } | Format-List | Out-String | ForEach-Object { Write-Information $_.TrimEnd() }
} else {
    Write-Warning "Could not retrieve federated credential: $($ficGetResponse.Content)"
}

Write-Information '--- GitHub Organization Secrets ---'
Write-Information "Organization:  $GitHubOrganization"
Write-Information 'Secrets set:   AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID'
Write-Information ''
Write-Information 'Next steps:'
Write-Information '  1. Assign RBAC roles to the managed identity principal on the Azure resources you need.'
Write-Information "     Example: New-AzRoleAssignment -ObjectId $($finalMi.PrincipalId) -RoleDefinitionName Contributor -Scope /subscriptions/$subscriptionId"
Write-Information '  2. Use azure/login@v2 in your GitHub Actions workflows with:'
Write-Information '       client-id:       ${{ secrets.AZURE_CLIENT_ID }}'
Write-Information '       tenant-id:       ${{ secrets.AZURE_TENANT_ID }}'
Write-Information '       subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}'
#endregion
